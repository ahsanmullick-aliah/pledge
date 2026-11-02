package pledgecc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const ClockSkew = 300

type Config struct {
	AAKeys             map[string]string `json:"aa_keys"`
	RegulatorPurposePK string            `json:"regulator_purpose_pk"`
	N                  int               `json:"n"`
	K                  int               `json:"k"`
}

type Cred struct {
	VK string `json:"vk"`
	AA string `json:"aa"`
}

// State is the read view the checks need; implemented over the Fabric stub
// in the chaincode and over maps in the tests.
type State interface {
	Config() (*Config, error)
	Credential(gid string) (*Cred, error)
	Revoked(gid string) (bool, error)
	Record(tau string) (map[string]interface{}, error)
	NonceSeen(gid, nonce string) (bool, error)
	EntryGID(id string) (string, error)
	PatientBound(psi string) (bool, error)
}

type AccessEvent struct {
	EntryID    string   `json:"entry_id"`
	GID        string   `json:"gid"`
	S          []int64  `json:"S"`
	Taus       []string `json:"taus"`
	Breakglass bool     `json:"breakglass"`
	TS         int64    `json:"ts"`
}

type Reject struct{ Reason string }

func (r *Reject) Error() string { return r.Reason }

func rej(format string, a ...interface{}) error { return &Reject{fmt.Sprintf(format, a...)} }

// ---------- field helpers ----------

func str(m map[string]interface{}, k string) (string, error) {
	v, ok := m[k].(string)
	if !ok {
		return "", rej("field %q missing or not a string", k)
	}
	return v, nil
}

func optStr(m map[string]interface{}, k string) (string, bool) {
	v, ok := m[k].(string)
	return v, ok
}

func num(v interface{}) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	return n.Int64()
}

func boolean(m map[string]interface{}, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func list(m map[string]interface{}, k string) []interface{} {
	l, _ := m[k].([]interface{})
	return l
}

func strList(l []interface{}) ([]string, error) {
	out := make([]string, len(l))
	for i, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("expected string")
		}
		out[i] = s
	}
	return out, nil
}

func signedBy(m map[string]interface{}, kind, vkHex, sigField string) ([]byte, bool) {
	d, err := Digest(kind, Body(m))
	if err != nil {
		return nil, false
	}
	sig, ok := m[sigField].(string)
	if !ok {
		return d, false
	}
	return d, BLSVerify(vkHex, sig, d)
}

// ---------- transactions ----------

func CheckCredential(st State, m map[string]interface{}) error {
	cfg, err := st.Config()
	if err != nil {
		return err
	}
	aa, err := str(m, "aa")
	if err != nil {
		return err
	}
	gid, err := str(m, "gid")
	if err != nil {
		return err
	}
	vk, ok := cfg.AAKeys[aa]
	if !ok {
		return rej("credential not signed by a known authority")
	}
	if _, good := signedBy(m, "cred", vk, "sig"); !good {
		return rej("credential not signed by a known authority")
	}
	if c, _ := st.Credential(gid); c != nil {
		return rej("GID already registered")
	}
	if _, err := str(m, "vk"); err != nil {
		return err
	}
	return nil
}

func CheckRevoke(st State, m map[string]interface{}) error {
	cfg, err := st.Config()
	if err != nil {
		return err
	}
	aa, _ := str(m, "aa")
	gid, err := str(m, "gid")
	if err != nil {
		return err
	}
	vk, ok := cfg.AAKeys[aa]
	if !ok {
		return rej("revocation not signed by a known authority")
	}
	if _, good := signedBy(m, "revoke", vk, "sig"); !good {
		return rej("revocation not signed by a known authority")
	}
	if c, _ := st.Credential(gid); c == nil {
		return rej("unknown GID")
	}
	return nil
}

// CheckPatient validates Reg_P: an AA-certified binding of a salted pseudonym to the
// patient's keys (paper Section V-B). rotate=true replaces an existing binding.
func CheckPatient(st State, m map[string]interface{}) error {
	cfg, err := st.Config()
	if err != nil {
		return err
	}
	aa, _ := str(m, "aa")
	psi, err := str(m, "psi")
	if err != nil {
		return err
	}
	vk, ok := cfg.AAKeys[aa]
	if !ok {
		return rej("patient registration not certified by a known authority")
	}
	if _, good := signedBy(m, "patient", vk, "sig"); !good {
		return rej("patient registration not certified by a known authority")
	}
	bound, err := st.PatientBound(psi)
	if err != nil {
		return err
	}
	if boolean(m, "rotate") && !bound {
		return rej("rotation for an unregistered patient")
	}
	if !boolean(m, "rotate") && bound {
		return rej("patient pseudonym already bound")
	}
	return nil
}

// CheckRecord validates a record registration or update. A registration that
// names "retires" re-keys a record: it registers a new tag and retires the old
// one, signed by the old tag's update key too (Section V-I). retires == tau
// retires a tag without a successor.
func CheckRecord(st State, m map[string]interface{}) (ownerVK string, err error) {
	tau, err := str(m, "tau")
	if err != nil {
		return "", err
	}
	owner, err := str(m, "owner_vk")
	if err != nil {
		return "", err
	}
	prev, err := st.Record(tau)
	if err != nil {
		return "", err
	}
	if prev != nil && boolean(prev, "retired") {
		return "", rej("record tag retired by a re-key")
	}
	if prev != nil {
		owner, _ = str(prev, "owner_vk")
	}
	d, good := signedBy(m, "record", owner, "sig")
	if !good {
		return "", rej("record update not signed by its owner")
	}
	retires, has := optStr(m, "retires")
	if has && retires == tau {
		if prev == nil {
			return "", rej("unknown record tag")
		}
	} else if has {
		old, err := st.Record(retires)
		if err != nil {
			return "", err
		}
		if prev != nil || old == nil {
			return "", rej("a re-key must register a new tag and retire an existing one")
		}
		if boolean(old, "retired") {
			return "", rej("record tag already retired")
		}
		oldOwner, _ := str(old, "owner_vk")
		rs, _ := optStr(m, "retire_sig")
		if !BLSVerify(oldOwner, rs, d) {
			return "", rej("retirement not signed by the old tag's owner")
		}
	}
	return owner, nil
}

func clinicianOK(st State, gid string) (*Cred, error) {
	c, err := st.Credential(gid)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, rej("unregistered clinician %s", gid)
	}
	if r, _ := st.Revoked(gid); r {
		return nil, rej("revoked clinician %s", gid)
	}
	return c, nil
}

func inPeriod(day string, period []interface{}) bool {
	if len(period) != 2 {
		return true
	}
	if s, ok := period[0].(string); ok && len(s) >= 10 && day < s[:10] {
		return false
	}
	if e, ok := period[1].(string); ok && len(e) >= 10 && day > e[:10] {
		return false
	}
	return true
}

// CheckAccess validates an access entry at ledger time `now` (unix seconds).
func CheckAccess(st State, m map[string]interface{}, now int64) (*AccessEvent, error) {
	cfg, err := st.Config()
	if err != nil {
		return nil, err
	}
	gid, err := str(m, "gid")
	if err != nil {
		return nil, err
	}
	cred, err := clinicianOK(st, gid)
	if err != nil {
		return nil, err
	}
	body, good := signedBy(m, "access", cred.VK, "sig")
	if !good {
		return nil, rej("bad clinician signature")
	}
	ts, err := num(m["ts"])
	if err != nil {
		return nil, rej("bad timestamp")
	}
	if ts-now > ClockSkew || now-ts > ClockSkew {
		return nil, rej("stale or future timestamp")
	}
	nonce, err := str(m, "nonce")
	if err != nil {
		return nil, err
	}
	if seen, _ := st.NonceSeen(gid, nonce); seen {
		return nil, rej("replayed nonce")
	}
	var S []int64
	seenIdx := map[int64]bool{}
	for _, x := range list(m, "S") {
		i, err := num(x)
		if err != nil || i < 1 || i > int64(cfg.N) || seenIdx[i] {
			return nil, rej("designated set S must name k distinct services")
		}
		seenIdx[i] = true
		S = append(S, i)
	}
	if len(S) != cfg.K {
		return nil, rej("designated set S must name k distinct services")
	}
	if prev, ok := optStr(m, "retry_of"); ok {
		g, _ := st.EntryGID(prev)
		if g != gid {
			return nil, rej("retry must reference the clinician's own committed entry")
		}
	}
	breakglass := boolean(m, "breakglass")
	if breakglass {
		co, ok := optStr(m, "cosigner")
		if !ok || co == gid {
			return nil, rej("break-glass needs a second clinician")
		}
		cc, err := clinicianOK(st, co)
		if err != nil {
			return nil, err
		}
		cs, _ := optStr(m, "cosig")
		if !BLSVerify(cc.VK, cs, body) {
			return nil, rej("bad co-signature")
		}
	}
	items := list(m, "items")
	if len(items) == 0 {
		return nil, rej("empty request")
	}
	day := time.Unix(now, 0).UTC().Format("2006-01-02")
	ev := &AccessEvent{EntryID: hex.EncodeToString(body), GID: gid, S: S, Breakglass: breakglass, TS: ts}
	for _, raw := range items {
		it, ok := raw.(map[string]interface{})
		if !ok {
			return nil, rej("malformed item")
		}
		tau, err := str(it, "tau")
		if err != nil {
			return nil, err
		}
		rec, err := st.Record(tau)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, rej("unknown record tag %.8s", tau)
		}
		if boolean(rec, "retired") {
			return nil, rej("record tag retired by a re-key")
		}
		salt, _ := str(rec, "salt")
		deny, _ := strList(list(rec, "deny"))
		tag := DenyTag(salt, gid, tau)
		for _, d := range deny {
			if d == tag {
				return nil, rej("clinician is on the record's deny list")
			}
		}
		var allowed []int64
		if breakglass {
			if !boolean(rec, "emergency") {
				return nil, rej("patient opted out of emergency access")
			}
			allowed = []int64{2} // ETREAT
		} else {
			if !inPeriod(day, list(rec, "period")) {
				return nil, rej("outside the consent period")
			}
			for _, p := range list(rec, "purposes") {
				v, err := num(p)
				if err != nil {
					return nil, rej("bad purpose list")
				}
				allowed = append(allowed, v)
			}
		}
		ctHex, err := strList(list(it, "purpose_ct"))
		if err != nil {
			return nil, rej("malformed purpose ciphertext")
		}
		var proof [][]string
		for _, b := range list(it, "proof") {
			bl, ok := b.([]interface{})
			if !ok {
				return nil, rej("malformed proof")
			}
			s, err := strList(bl)
			if err != nil {
				return nil, rej("malformed proof")
			}
			proof = append(proof, s)
		}
		P, _ := str(rec, "patient_purpose_pk")
		if err := VerifyPurpose(ctHex, proof, P, cfg.RegulatorPurposePK, allowed, PurposeCtx(gid, tau, nonce)); err != nil {
			return nil, rej("purpose proof invalid or purpose not allowed")
		}
		ev.Taus = append(ev.Taus, tau)
	}
	return ev, nil
}

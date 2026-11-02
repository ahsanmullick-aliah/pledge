package pledgecc

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vecState struct {
	Cfg     Config                            `json:"config"`
	Creds   map[string]Cred                   `json:"credentials"`
	Rev     []string                          `json:"revoked"`
	Records map[string]json.RawMessage        `json:"records"`
	Nonces  [][]string                        `json:"nonces"`
	Entries map[string]string                 `json:"entries"`
	Pats    []string                          `json:"patients"`
}

func (s *vecState) PatientBound(p string) (bool, error) {
	for _, x := range s.Pats {
		if x == p {
			return true, nil
		}
	}
	return false, nil
}

func (s *vecState) Config() (*Config, error) { return &s.Cfg, nil }
func (s *vecState) Credential(g string) (*Cred, error) {
	if c, ok := s.Creds[g]; ok {
		return &c, nil
	}
	return nil, nil
}
func (s *vecState) Revoked(g string) (bool, error) {
	for _, r := range s.Rev {
		if r == g {
			return true, nil
		}
	}
	return false, nil
}
func (s *vecState) Record(t string) (map[string]interface{}, error) {
	raw, ok := s.Records[t]
	if !ok {
		return nil, nil
	}
	return Decode(raw)
}
func (s *vecState) NonceSeen(g, n string) (bool, error) {
	for _, x := range s.Nonces {
		if x[0] == g && x[1] == n {
			return true, nil
		}
	}
	return false, nil
}
func (s *vecState) EntryGID(id string) (string, error) { return s.Entries[id], nil }

type vector struct {
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Tx     json.RawMessage `json:"tx"`
	Now    int64           `json:"now"`
	State  vecState        `json:"state"`
	OK     bool            `json:"ok"`
	Reason string          `json:"reason"`
}

func TestCrossLanguageVectors(t *testing.T) {
	Init()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		m, err := Decode(v.Tx)
		if err != nil {
			t.Fatal(err)
		}
		st := v.State
		switch v.Kind {
		case "access":
			_, err = CheckAccess(&st, m, v.Now)
		case "cred":
			err = CheckCredential(&st, m)
		case "revoke":
			err = CheckRevoke(&st, m)
		case "record":
			_, err = CheckRecord(&st, m)
		case "patient":
			err = CheckPatient(&st, m)
		}
		gotOK := err == nil
		if gotOK != v.OK {
			t.Errorf("%s: python ok=%v (%s), go ok=%v (%v)", v.Name, v.OK, v.Reason, gotOK, err)
			continue
		}
		if !gotOK && !strings.HasPrefix(err.Error(), strings.SplitN(v.Reason, " ", 2)[0]) {
			t.Logf("%s: reasons differ in wording: python=%q go=%q", v.Name, v.Reason, err)
		}
		t.Logf("%-32s ok=%v %v", v.Name, gotOK, err)
	}
}

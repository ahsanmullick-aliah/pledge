package pledgecc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Canon serializes a decoded JSON value the way Python's
// json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True) does,
// for the ASCII-only values PLEDGE uses.
func Canon(v interface{}) ([]byte, error) {
	if err := asciiOnly(v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func asciiOnly(v interface{}) error {
	switch t := v.(type) {
	case string:
		for i := 0; i < len(t); i++ {
			if t[i] >= 0x7f || t[i] < 0x20 {
				return fmt.Errorf("non-ASCII or control character in string")
			}
		}
	case map[string]interface{}:
		for k, x := range t {
			if err := asciiOnly(k); err != nil {
				return err
			}
			if err := asciiOnly(x); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, x := range t {
			if err := asciiOnly(x); err != nil {
				return err
			}
		}
	}
	return nil
}

// Digest = SHA-256("PLEDGE|<kind>|" || canon(body)).
func Digest(kind string, body interface{}) ([]byte, error) {
	c, err := Canon(body)
	if err != nil {
		return nil, err
	}
	return sha(append([]byte("PLEDGE|"+kind+"|"), c...)), nil
}

// Decode parses a wire transaction keeping numbers exact.
func Decode(raw []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// Body returns the transaction without its signature fields.
func Body(m map[string]interface{}) map[string]interface{} {
	b := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k == "sig" || k == "cosig" || k == "retire_sig" {
			continue
		}
		b[k] = v
	}
	return b
}

func PurposeCtx(gid, tau, nonce string) []byte {
	d, _ := Digest("purpose-ctx", map[string]interface{}{"gid": gid, "tau": tau, "nonce": nonce})
	return d
}

func DenyTag(saltHex, gid, tau string) string {
	d, _ := Digest("deny", map[string]interface{}{"salt": saltHex, "gid": gid, "tau": tau})
	return hex.EncodeToString(d)
}

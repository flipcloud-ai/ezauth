package config

import (
	"fmt"
	"reflect"
)

// SecretRef is a polymorphic config field that resolves secret bytes
// from an inline base64 string or a file source.
type SecretRef struct {
	Type string // "file" or "hashicorp"; empty = inline or auto
	Path string // for type=file
	Key  string // for type=file with YAML/JSON key extraction; optional
	raw  []byte // resolved bytes, set by the secret driver
}

// Bytes returns a copy of the resolved secret bytes.
func (sr SecretRef) Bytes() []byte {
	if len(sr.raw) == 0 {
		return nil
	}
	out := make([]byte, len(sr.raw))
	copy(out, sr.raw)
	return out
}

// String returns the resolved secret as a plain string. Returns empty string if not resolved.
func (sr SecretRef) String() string {
	return string(sr.raw)
}

// IsZero reports whether the SecretRef was not configured (no inline value, no file source).
func (sr SecretRef) IsZero() bool {
	return sr.Type == "" && sr.Path == "" && sr.Key == "" && len(sr.raw) == 0
}

// SetRaw stores resolved secret bytes. For use by the secret driver only.
func (sr *SecretRef) SetRaw(b []byte) {
	cp := make([]byte, len(b))
	copy(cp, b)
	sr.raw = cp
}

// NewResolvedSecretRef creates a SecretRef with pre-resolved bytes.
func NewResolvedSecretRef(raw []byte) SecretRef {
	b := make([]byte, len(raw))
	copy(b, raw)
	return SecretRef{raw: b}
}

// SecretRefDecodeHookFunc returns a mapstructure decode hook that handles SecretRef fields.
// From string: use the value as-is (plaintext).
// From map: read type/path/key fields; resolution is deferred to the secret driver.
func SecretRefDecodeHookFunc() interface{} {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(SecretRef{}) {
			return data, nil
		}

		switch v := data.(type) {
		case string:
			if v == "" {
				return SecretRef{}, nil
			}
			return SecretRef{raw: []byte(v)}, nil

		case map[string]interface{}:
			sr := SecretRef{}
			if t, ok := v["type"].(string); ok {
				sr.Type = t
			}
			if p, ok := v["path"].(string); ok {
				sr.Path = p
			}
			if k, ok := v["key"].(string); ok {
				sr.Key = k
			}
			return sr, nil

		default:
			return nil, fmt.Errorf("cannot decode %T into SecretRef", data)
		}
	}
}

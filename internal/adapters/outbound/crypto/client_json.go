package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// Exact bounded member names avoid encoding/json's duplicate-last-wins and
// case-insensitive struct matching at the assertion and registered-key boundary.
func clientObject(data []byte, names ...string) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[name]; exists {
			return nil, false
		}
		allowed := false
		for _, known := range names {
			if name == known {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}
func strictClientKeys(data []byte) bool {
	object, ok := clientObject(data, "keys")
	if !ok {
		return false
	}
	var keys []json.RawMessage
	if json.Unmarshal(object["keys"], &keys) != nil || len(keys) == 0 || len(keys) > 8 {
		return false
	}
	for _, key := range keys {
		if _, ok := clientObject(key, "kid", "kty", "use", "alg", "crv", "x", "y", "n", "e"); !ok {
			return false
		}
	}
	return true
}
func strictClientAssertion(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	if _, ok := clientObject(header, "alg", "kid", "typ"); !ok {
		return false
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	if _, ok := clientObject(claims, "iss", "sub", "aud", "jti", "iat", "exp", "nbf"); !ok {
		return false
	}
	return true
}

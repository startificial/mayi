package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// decode accepts extension members but rejects duplicate keys and excessive
// nesting, rather than interpreting ambiguous upstream JSON with last-wins.
func decode(data []byte, v any) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return authenticationJSONError()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := jsonValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return authenticationJSONError()
	}
	return json.Unmarshal(data, v)
}
func authenticationJSONError() error { return errors.New("invalid upstream JSON") }
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return authenticationJSONError()
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[strings.ToLower(key)] {
					return authenticationJSONError()
				}
				seen[strings.ToLower(key)] = true
				if e = jsonValue(d, depth+1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := jsonValue(d, depth+1); e != nil {
					return e
				}
			}
		default:
			return authenticationJSONError()
		}
		_, err = d.Token()
	}
	return err
}

func requiredMembers(data []byte, names ...string) bool {
	var members map[string]json.RawMessage
	if decode(data, &members) != nil {
		return false
	}
	for _, name := range names {
		value, ok := members[name]
		if !ok || string(value) == "null" {
			return false
		}
	}
	return true
}

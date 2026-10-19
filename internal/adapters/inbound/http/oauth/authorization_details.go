package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

const MaxAuthorizationDetailsBytes = 32 << 10

var ErrInvalidAuthorizationDetails = errors.New("invalid authorization details")

// DecodeAuthorizationDetails maps RFC 9396's envelope into the initial document
// profile. It is not a handler and does not establish client/user authority.
// The profile must be selected from trusted tenant/resource configuration. No
// endpoint accepts RAR until PAR, approval and credential enforcement are wired.
func DecodeAuthorizationDetails(raw string, profile resources.DocumentProfile) (grants.ObjectCeiling, error) {
	if len(raw) == 0 || len(raw) > MaxAuthorizationDetailsBytes || !utf8.ValidString(raw) {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	spec := profile.Snapshot()
	d := json.NewDecoder(strings.NewReader(raw))
	if !delimiter(d, '[') {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	var details []grants.ObjectDetail
	for d.More() {
		if len(details) >= grants.MaxObjectDetails {
			return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
		}
		detail, err := documentDetail(d, spec.Resource)
		if err != nil {
			return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
		}
		details = append(details, detail)
	}
	if !delimiter(d, ']') {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	if _, err := d.Token(); err != io.EOF {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	ceiling, err := profile.ValidateRequest(spec.Scope, spec.Resource, details)
	if err != nil {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	// Keep the accepted envelope representable under the same response bound,
	// including JSON escaping expansion. Never accept authority we cannot emit.
	if _, err := EncodeAuthorizationDetails(ceiling, profile); err != nil {
		return grants.ObjectCeiling{}, ErrInvalidAuthorizationDetails
	}
	return ceiling, nil
}

// The fixed grammar accepts exactly array -> object -> strings/string arrays;
// recursive values and arbitrary extension members never enter the domain.
// Token parsing avoids encoding/json's last-wins duplicate member behavior and
// case-insensitive struct field matching, including escaped member names.
func documentDetail(d *json.Decoder, resource string) (grants.ObjectDetail, error) {
	var detail grants.ObjectDetail
	if !delimiter(d, '{') {
		return detail, ErrInvalidAuthorizationDetails
	}
	seen := make(map[string]bool, 4)
	for d.More() {
		key, err := jsonString(d)
		if err != nil || seen[key] {
			return grants.ObjectDetail{}, ErrInvalidAuthorizationDetails
		}
		seen[key] = true
		switch key {
		case "type":
			detail.Type, err = jsonString(d)
		case "identifier":
			detail.Identifier, err = jsonString(d)
		case "actions":
			detail.Actions, err = jsonStrings(d, grants.MaxObjectActions)
		case "locations":
			var locations []string
			locations, err = jsonStrings(d, 1)
			if err == nil && locations[0] != resource {
				err = ErrInvalidAuthorizationDetails
			}
		default:
			err = ErrInvalidAuthorizationDetails
		}
		if err != nil {
			return grants.ObjectDetail{}, ErrInvalidAuthorizationDetails
		}
	}
	if len(seen) != 4 || !delimiter(d, '}') {
		return grants.ObjectDetail{}, ErrInvalidAuthorizationDetails
	}
	return detail, nil
}

func delimiter(d *json.Decoder, want json.Delim) bool {
	token, err := d.Token()
	return err == nil && token == want
}
func jsonString(d *json.Decoder) (string, error) {
	token, err := d.Token()
	s, ok := token.(string)
	if err != nil || !ok {
		return "", ErrInvalidAuthorizationDetails
	}
	return s, nil
}
func jsonStrings(d *json.Decoder, limit int) ([]string, error) {
	if !delimiter(d, '[') {
		return nil, ErrInvalidAuthorizationDetails
	}
	var values []string
	for d.More() {
		if len(values) >= limit {
			return nil, ErrInvalidAuthorizationDetails
		}
		value, err := jsonString(d)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if !delimiter(d, ']') || len(values) == 0 {
		return nil, ErrInvalidAuthorizationDetails
	}
	return values, nil
}

type documentDetailDTO struct {
	Type       string   `json:"type"`
	Locations  []string `json:"locations"`
	Identifier string   `json:"identifier"`
	Actions    []string `json:"actions"`
}

// EncodeAuthorizationDetails emits only validated standard fields. It requires
// the same trusted profile snapshot used for the assigned ceiling, rather than
// serializing arbitrary JSON supplied by a client or persistence record.
func EncodeAuthorizationDetails(ceiling grants.ObjectCeiling, profile resources.DocumentProfile) ([]byte, error) {
	s := ceiling.Snapshot()
	if _, err := profile.ValidateRequest(s.Scope, s.Resource, s.Details); err != nil {
		return nil, ErrInvalidAuthorizationDetails
	}
	details := make([]documentDetailDTO, 0, len(s.Details))
	for _, detail := range s.Details {
		details = append(details, documentDetailDTO{Type: detail.Type, Locations: []string{s.Resource}, Identifier: detail.Identifier, Actions: detail.Actions})
	}
	data, err := json.Marshal(details)
	if err != nil || len(data) > MaxAuthorizationDetailsBytes {
		return nil, ErrInvalidAuthorizationDetails
	}
	return data, nil
}

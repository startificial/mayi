package delivery

import "context"

type RequestMetadata struct{ RequestID, IP, UserAgent string }
type metadataKey struct{}

// WithRequestMetadata accepts only bounded, credential-free transport metadata.
// The HTTP adapter establishes peer trust; no caller-supplied request ID is used.
func WithRequestMetadata(ctx context.Context, value RequestMetadata) context.Context {
	previous := Metadata(ctx)
	if value.RequestID != "" {
		valid := len(value.RequestID) == 32
		for _, c := range value.RequestID {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
			}
		}
		if valid {
			previous.RequestID = value.RequestID
		}
	}
	if value.IP != "" && len(value.IP) <= 45 {
		valid := true
		for _, c := range value.IP {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '.' || c == ':') {
				valid = false
			}
		}
		if valid {
			previous.IP = value.IP
		}
	}
	if len(value.UserAgent) <= 512 {
		valid := true
		for _, c := range value.UserAgent {
			if c < 0x20 || c > 0x7e {
				valid = false
			}
		}
		if valid {
			previous.UserAgent = value.UserAgent
		}
	}
	return context.WithValue(ctx, metadataKey{}, previous)
}
func Metadata(ctx context.Context) RequestMetadata {
	value, _ := ctx.Value(metadataKey{}).(RequestMetadata)
	return value
}

package status

import (
	"context"
	"github.com/startificial/mayi/internal/services/resource"
)

// PermissionBridge maps an SDK-owned callback to the consuming service port.
type PermissionBridge struct {
	callback func(context.Context, resource.Decision, func(context.Context) error) error
}

var _ resource.PermissionGuard = (*PermissionBridge)(nil)

func NewPermissionBridge(fn func(context.Context, resource.Decision, func(context.Context) error) error) *PermissionBridge {
	return &PermissionBridge{fn}
}
func (b *PermissionBridge) WithPermission(ctx context.Context, d resource.Decision, fn func(context.Context) error) error {
	if b.callback == nil {
		return resource.ErrUnavailable
	}
	return b.callback(ctx, d, fn)
}

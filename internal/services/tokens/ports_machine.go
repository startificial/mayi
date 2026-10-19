package tokens

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

type MachinePolicy struct {
	Ceiling                                     grants.ObjectCeiling
	Scopes                                      []string
	Profiles                                    []resources.ObjectProfile
	AccessSeconds, GrantSeconds, SigningVersion int
	RequireBinding, Opaque                      bool
}
type MachineStore interface {
	RunMachine(context.Context, Caller, string, func(MachineTransaction) error) error
}
type MachineTransaction interface {
	MachinePolicy(context.Context) (MachinePolicy, error)
	CommitMachine(context.Context, Issuance) error
}

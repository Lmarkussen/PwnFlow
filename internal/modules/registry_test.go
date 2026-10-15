package modules

import (
	"context"
	"testing"
)

type fake struct{}

func (fake) ID() string                                      { return "x" }
func (fake) Name() string                                    { return "x" }
func (fake) ToolFamily() ToolFamily                          { return ToolFamilyNetExec }
func (fake) Category() Category                              { return CategoryEnumeration }
func (fake) Description() string                             { return "" }
func (fake) Tool() string                                    { return "" }
func (fake) Protocol() Protocol                              { return ProtocolLDAP }
func (fake) Prerequisites() []string                         { return nil }
func (fake) RequiredPrivileges() []string                    { return nil }
func (fake) OutputFile() string                              { return "" }
func (fake) Sensitivity() Sensitivity                        { return SensitivityStandard }
func (fake) ReadOnly() bool                                  { return true }
func (fake) SecondaryConnections() []string                  { return nil }
func (fake) Check(_ context.Context, _ *Runtime) error       { return nil }
func (fake) Run(context.Context, *Runtime, OutputSink) error { return nil }

func TestRegistryRegistration(t *testing.T) {
	r := &Registry{}
	r.Register(fake{})
	if got := len(r.All()); got != 1 {
		t.Fatalf("got %d modules", got)
	}
}

func TestRegistryFiltersByCategory(t *testing.T) {
	r := &Registry{}
	r.Register(fake{})
	if got := len(r.ByCategory(CategoryEnumeration)); got != 1 {
		t.Fatalf("got %d modules", got)
	}
	if got := len(r.ByCategory(CategoryCredentialAuditing)); got != 0 {
		t.Fatalf("got %d inactive modules", got)
	}
}

func TestRegistryFiltersByToolFamilyAndProtocol(t *testing.T) {
	r := &Registry{}
	r.Register(fake{})
	if got := len(r.ByToolFamily(ToolFamilyNetExec)); got != 1 {
		t.Fatalf("got %d NetExec modules", got)
	}
	if got := len(r.ByProtocol(ProtocolLDAP)); got != 1 {
		t.Fatalf("got %d LDAP modules", got)
	}
	if got := len(r.ByProtocol(ProtocolSMB)); got != 0 {
		t.Fatalf("got %d SMB modules", got)
	}
}

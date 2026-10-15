package ldaptransport

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
)

// The identity formats mirror the sequence that works against Active Directory:
// the bare name, the UPN, then the down-level DOMAIN\user form.
func TestSimpleBindFormats(t *testing.T) {
	got := strings.Join(simpleBindFormats("audituser", "corp.example"), ",")
	want := `audituser,audituser@corp.example,CORP\audituser`
	if got != want {
		t.Fatalf("formats = %q, want %q", got, want)
	}
	for identity, wantFormats := range map[string]string{
		"user@corp.example": `user@corp.example`,
		`CORP\user`:         `CORP\user`,
	} {
		formats := simpleBindFormats(identity, "corp.example")
		if len(formats) != 1 || formats[0] != wantFormats {
			t.Fatalf("explicit identity %q produced %v", identity, formats)
		}
	}
	if formats := simpleBindFormats("   ", "corp.example"); len(formats) != 0 {
		t.Fatalf("blank username produced %v", formats)
	}
	if formats := simpleBindFormats("user", ""); len(formats) != 1 {
		t.Fatalf("missing domain produced %v", formats)
	}
}

// fakeLDAP records the bind sequence and answers per mechanism.
type fakeLDAP struct {
	ntlmErr    error
	accepted   map[string]bool
	ntlmCalls  int
	simpleVals []string
}

func (f *fakeLDAP) NTLMBind(_, _, _ string) error {
	f.ntlmCalls++
	return f.ntlmErr
}

func (f *fakeLDAP) Bind(identity, _ string) error {
	f.simpleVals = append(f.simpleVals, identity)
	if f.accepted[identity] {
		return nil
	}
	return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("simple bind refused")}
}

type ldapAuthError struct{}

func (*ldapAuthError) Error() string { return "invalid credentials" }

func TestBindOverTLSPrefersNTLM(t *testing.T) {
	client := &fakeLDAP{accepted: map[string]bool{}}
	if err := bindOverTLS(client, config.Config{Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}); err != nil {
		t.Fatalf("NTLM bind should have succeeded: %v", err)
	}
	if client.ntlmCalls != 1 || len(client.simpleVals) != 0 {
		t.Fatalf("unexpected sequence: ntlm=%d simple=%v", client.ntlmCalls, client.simpleVals)
	}
}

// When the controller refuses NTLM, the same credentials are offered as a simple
// bind in the formats Active Directory accepts - this is the operator's case.
func TestBindOverTLSFallsBackToSimpleBindFormats(t *testing.T) {
	client := &fakeLDAP{ntlmErr: &ldapAuthError{}, accepted: map[string]bool{"audituser@corp.example": true}}
	if err := bindOverTLS(client, config.Config{Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}); err != nil {
		t.Fatalf("simple bind fallback failed: %v", err)
	}
	if client.ntlmCalls != 1 {
		t.Fatalf("NTLM was attempted %d times", client.ntlmCalls)
	}
	want := []string{"audituser", "audituser@corp.example"}
	if strings.Join(client.simpleVals, ",") != strings.Join(want, ",") {
		t.Fatalf("simple bind sequence = %v, want %v", client.simpleVals, want)
	}
}

// Every mechanism failing is reported without leaking the password.
func TestBindOverTLSReportsEveryFailure(t *testing.T) {
	client := &fakeLDAP{ntlmErr: &ldapAuthError{}, accepted: map[string]bool{}}
	err := bindOverTLS(client, config.Config{Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"})
	if err == nil {
		t.Fatal("expected failure")
	}
	message := err.Error()
	for _, want := range []string{"NTLM bind failed", "simple bind failed", "***"} {
		if !strings.Contains(message, want) {
			t.Fatalf("diagnostic missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, "Sup3rSecret") {
		t.Fatalf("diagnostic leaked the password: %s", message)
	}
	if len(client.simpleVals) != 3 {
		t.Fatalf("expected three identity formats, got %v", client.simpleVals)
	}
}

// A refused credential must stay an authentication failure, not a transport one.
func TestBindFailureIsClassifiedAsAuthentication(t *testing.T) {
	refused := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data 52e")}
	client := &fakeLDAP{ntlmErr: refused, accepted: map[string]bool{}}
	err := bindOverTLS(client, config.Config{Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"})
	if err == nil {
		t.Fatal("expected a wrapped failure")
	}
	if Classify(err) != KindAuthentication {
		t.Fatalf("classified as %q", Classify(err))
	}
}

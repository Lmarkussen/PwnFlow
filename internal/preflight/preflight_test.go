package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
)

func TestBindIdentityUsesUPN(t *testing.T) {
	if got := BindIdentity("svc-audit", "corp.example"); got != "svc-audit@corp.example" {
		t.Fatalf("got %q", got)
	}
	if got := BindIdentity("user@corp.example", "corp.example"); got != "user@corp.example" {
		t.Fatalf("qualified identity changed to %q", got)
	}
}

func transportFailure(kind ldaptransport.Kind) error {
	return &ldaptransport.Error{
		Kind:     kind,
		Attempts: []ldaptransport.Attempt{{Transport: ldaptransport.LDAP, Endpoint: "198.51.100.10:389", Kind: kind, Err: errors.New("attempt failed")}},
	}
}

// Each transport failure keeps its own kind, so a signing requirement is never
// reported as bad credentials and an unreachable host is never reported as a
// trust problem.
func TestClassifyBindErrors(t *testing.T) {
	for name, test := range map[string]struct {
		kind ldaptransport.Kind
		want FailureKind
	}{
		"signing required": {ldaptransport.KindSigning, FailureSigning},
		"invalid creds":    {ldaptransport.KindAuthentication, FailureAuthentication},
		"untrusted cert":   {ldaptransport.KindTLS, FailureTLS},
		"unreachable":      {ldaptransport.KindConnectivity, FailureConnectivity},
		"unsupported":      {ldaptransport.KindProtocol, FailureProtocol},
	} {
		err := classifyBindFailure(transportFailure(test.kind), false)
		if got := ClassifyBindError(err); got != test.want {
			t.Errorf("%s classified as %q, want %q", name, got, test.want)
		}
		if !strings.Contains(err.Error(), string(test.want)) {
			t.Errorf("%s message omits the kind: %v", name, err)
		}
	}
}

// A certificate failure names the opt-in without ever taking it silently.
func TestCertificateFailureNamesTheExplicitOptIn(t *testing.T) {
	withHint := classifyBindFailure(transportFailure(ldaptransport.KindTLS), false)
	if !strings.Contains(withHint.Error(), "--insecure-skip-verify") {
		t.Fatalf("hint missing: %v", withHint)
	}
	optedIn := classifyBindFailure(transportFailure(ldaptransport.KindTLS), true)
	if strings.Contains(optedIn.Error(), "--insecure-skip-verify") {
		t.Fatalf("hint repeated although verification was already skipped: %v", optedIn)
	}
}

// Both attempts are explained when neither transport works.
func TestFailureExplainsEveryAttempt(t *testing.T) {
	aggregate := &ldaptransport.Error{
		Kind: ldaptransport.KindSigning,
		Attempts: []ldaptransport.Attempt{
			{Transport: ldaptransport.LDAP, Endpoint: "198.51.100.10:389", Kind: ldaptransport.KindSigning, Err: errors.New("integrity checking required")},
			{Transport: ldaptransport.LDAPS, Endpoint: "198.51.100.10:636", Kind: ldaptransport.KindSigning, Err: errors.New("integrity checking required")},
		},
	}
	err := classifyBindFailure(aggregate, false)
	message := err.Error()
	for _, want := range []string{"LDAP 198.51.100.10:389", "LDAPS 198.51.100.10:636", "signing"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q: %s", want, message)
		}
	}
}

// An unrelated error is treated as an authentication failure rather than being
// silently accepted.
func TestUnknownFailureIsNotAccepted(t *testing.T) {
	err := classifyBindFailure(errors.New("boom"), false)
	if ClassifyBindError(err) != FailureAuthentication {
		t.Fatalf("unexpected kind: %v", err)
	}
}

// The preflight refuses to proceed without its dependency, and it never reports
// success for an unperformed bind.
func TestRunRequiresTheDependencyAndNeverFakesSuccess(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	result, err := Run(context.Background(), config.Config{Target: "198.51.100.10", Domain: "corp.example", Username: "user", Password: "secret"}, ldaptransport.Options{})
	if err == nil {
		t.Fatalf("Run reported success without its dependency: %#v", result)
	}
	if !strings.Contains(err.Error(), "nxc") {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Transport != "" || result.Endpoint != "" {
		t.Fatalf("Run reported a session it never established: %#v", result)
	}
}

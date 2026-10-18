package preflight

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/go-ldap/ldap/v3"
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

func TestDiagnosticCategoriesFromStructuredErrors(t *testing.T) {
	tests := map[string]struct {
		err      error
		category DiagnosticCategory
		phrase   string
	}{
		"ldap 49 52e": {
			err:      &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data 52e")},
			category: CategoryAuthenticationRejected,
			phrase:   "does not by itself prove that the password is incorrect",
		},
		"ldap signing": {
			err:      &ldap.Error{ResultCode: ldap.LDAPResultStrongAuthRequired, Err: errors.New("strongerAuthRequired")},
			category: CategoryLDAPIntegrityRequired,
			phrase:   "requires signing or integrity protection",
		},
		"refused": {
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
			category: CategoryConnectionRefused,
			phrase:   "explicitly refused",
		},
		"timeout": {
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded},
			category: CategoryConnectionTimeout,
			phrase:   "timed out",
		},
		"dns": {
			err:      &net.DNSError{Name: "dc.example.test", Err: "no such host"},
			category: CategoryTargetUnreachable,
			phrase:   "No usable network connection",
		},
		"tls identity": {
			err:      x509.HostnameError{Certificate: &x509.Certificate{}, Host: "10.1.10.40"},
			category: CategoryTLSIdentityFailed,
			phrase:   "identity validation",
		},
		"tls trust": {
			err:      x509.UnknownAuthorityError{},
			category: CategoryTLSTrustFailed,
			phrase:   "certificate validation",
		},
		"tls handshake": {
			err:      tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			category: CategoryTLSHandshakeFailed,
			phrase:   "TLS negotiation",
		},
		"cancelled": {
			err:      context.Canceled,
			category: CategoryCancelled,
			phrase:   "cancelled",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := classifyBindFailureWithContext(&ldaptransport.Error{Kind: ldaptransport.KindConnectivity, Attempts: []ldaptransport.Attempt{{Transport: ldaptransport.LDAP, Endpoint: "dc:389", Err: test.err, Kind: ldaptransport.Classify(test.err)}}}, false, "10.1.10.40", "sccm.lab", "secret")
			failure := new(Failure)
			if !errors.As(err, &failure) || failure.Category != test.category {
				t.Fatalf("category=%q error=%v", failure.Category, err)
			}
			if !strings.Contains(err.Error(), test.phrase) {
				t.Fatalf("message missing %q: %v", test.phrase, err)
			}
		})
	}
}

func TestDiagnosticPrecedencePrefersExplicitLDAPRejection(t *testing.T) {
	err := &ldaptransport.Error{Kind: ldaptransport.KindConnectivity, Attempts: []ldaptransport.Attempt{
		{Transport: ldaptransport.LDAP, Endpoint: "dc:389", Kind: ldaptransport.KindAuthentication, Err: &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data 52e")}},
		{Transport: ldaptransport.LDAPS, Endpoint: "dc:636", Kind: ldaptransport.KindConnectivity, Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}},
	}}
	got := classifyBindFailureWithContext(err, false, "10.1.10.40", "sccm.lab", "secret")
	if !strings.Contains(got.Error(), "authentication_rejected") || !strings.Contains(got.Error(), "49") {
		t.Fatalf("explicit LDAP rejection was not preferred: %v", got)
	}
}

func TestDiagnosticRecognizesADAccountStateSubcodes(t *testing.T) {
	tests := map[string]DiagnosticCategory{
		"525": CategoryAccountNotFound,
		"532": CategoryPasswordExpired,
		"533": CategoryAccountDisabled,
		"701": CategoryAccountExpired,
		"773": CategoryPasswordExpired,
		"775": CategoryAccountLocked,
	}
	for subcode, want := range tests {
		err := &ldaptransport.Error{Kind: ldaptransport.KindAuthentication, Attempts: []ldaptransport.Attempt{{Transport: ldaptransport.LDAP, Endpoint: "dc:389", Kind: ldaptransport.KindAuthentication, Err: &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data " + subcode)}}}}
		failure, ok := classifyBindFailureWithContext(err, false, "10.1.10.40", "sccm.lab", "secret").(*Failure)
		if !ok || failure.Category != want {
			t.Errorf("subcode %s category=%q want=%q", subcode, failure.Category, want)
		}
	}
}

func TestDiagnosticRedactsSecrets(t *testing.T) {
	err := classifyBindFailureWithContext(errors.New("bind failed password=SuperSecret token=abc123"), false, "10.1.10.40", "sccm.lab", "SuperSecret")
	text := err.Error()
	for _, secret := range []string{"SuperSecret", "abc123"} {
		if strings.Contains(text, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, text)
		}
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

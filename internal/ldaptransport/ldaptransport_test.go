package ldaptransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
)

// fakeBinder records the attempts a connector makes and answers with scripted
// failures, so the transport policy is exercised without a domain controller.
type fakeBinder struct {
	results map[Transport]error
	calls   []Transport
	options []Options
	targets []string
}

func (f *fakeBinder) Bind(_ context.Context, cfg config.Config, transport Transport, options Options) error {
	f.calls = append(f.calls, transport)
	f.options = append(f.options, options)
	f.targets = append(f.targets, cfg.Target)
	return f.results[transport]
}

func signingRequired() error {
	return &ldap.Error{ResultCode: ldap.LDAPResultStrongAuthRequired, Err: errors.New("00002028: The server requires binds to turn on integrity checking")}
}

func invalidCredentials() error {
	return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("80090308: LdapErr: data 52e")}
}

func connectivity() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func certUntrusted() error {
	// crypto/x509 reports verification problems as value types; Go's TLS stack
	// wraps them in *tls.CertificateVerificationError, which is also covered.
	return x509.UnknownAuthorityError{}
}

func testConfig() config.Config {
	return config.Config{Target: "198.51.100.10", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
}

func TestConnectSucceedsOverPlainLDAP(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{}}
	session, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("plain LDAP bind failed: %v", err)
	}
	if session.Transport != LDAP || session.Endpoint != "198.51.100.10:389" {
		t.Fatalf("unexpected session: %#v", session)
	}
	if len(binder.calls) != 1 {
		t.Fatalf("expected a single attempt, got %v", binder.calls)
	}
}

// The failure the operator hit: the domain requires signing, so the unsigned
// bind is refused and the same credentials are retried over LDAPS.
func TestConnectFallsBackToLDAPSWhenSigningIsRequired(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired()}}
	session, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("LDAPS fallback failed: %v", err)
	}
	if session.Transport != LDAPS || session.Endpoint != "198.51.100.10:636" {
		t.Fatalf("unexpected session: %#v", session)
	}
	if len(binder.calls) != 2 || binder.calls[0] != LDAP || binder.calls[1] != LDAPS {
		t.Fatalf("unexpected attempt sequence: %v", binder.calls)
	}
}

// An unreachable plain endpoint is also worth retrying over TLS, but only once.
func TestConnectFallsBackToLDAPSWhenLDAPIsUnreachable(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: connectivity()}}
	session, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("LDAPS fallback failed: %v", err)
	}
	if session.Transport != LDAPS {
		t.Fatalf("unexpected transport: %s", session.Transport)
	}
	if len(binder.calls) != 2 {
		t.Fatalf("attempt sequence was not bounded: %v", binder.calls)
	}
}

func TestConnectFallsBackToStartTLSWhenLDAPSIsUnreachable(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired(), LDAPS: connectivity()}}
	session, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("StartTLS fallback failed: %v", err)
	}
	if session.Transport != StartTLS || session.Endpoint != "198.51.100.10:389" {
		t.Fatalf("unexpected session: %#v", session)
	}
	if len(binder.calls) != 3 {
		t.Fatalf("unexpected attempt sequence: %v", binder.calls)
	}
}

// Wrong credentials are wrong on every transport: exactly one attempt, and the
// kind stays "authentication" so it is never mistaken for a signing problem.
func TestConnectDoesNotRetryInvalidCredentials(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: invalidCredentials()}}
	_, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err == nil {
		t.Fatal("invalid credentials were accepted")
	}
	if len(binder.calls) != 1 || binder.calls[0] != LDAP {
		t.Fatalf("credentials were retried: %v", binder.calls)
	}
	var transportErr *Error
	if !errors.As(err, &transportErr) || transportErr.Kind != KindAuthentication {
		t.Fatalf("unexpected classification: %v", err)
	}
}

// A certificate the trust store does not accept is a trust problem, not a
// transport problem: no other transport, and no silent skip.
func TestConnectReportsCertificateFailureWithoutRetrying(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired(), LDAPS: certUntrusted()}}
	_, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err == nil {
		t.Fatal("untrusted certificate was accepted")
	}
	if len(binder.calls) != 2 {
		t.Fatalf("unexpected attempt sequence: %v", binder.calls)
	}
	var transportErr *Error
	if !errors.As(err, &transportErr) || transportErr.Kind != KindTLS {
		t.Fatalf("certificate failure was not classified as TLS: %v", err)
	}
	if !strings.Contains(err.Error(), "LDAPS") || !strings.Contains(err.Error(), "198.51.100.10:636") {
		t.Fatalf("diagnostic does not name the LDAPS attempt: %v", err)
	}
}

// When both transports fail, the diagnostic explains each attempt.
func TestConnectExplainsEveryAttemptWhenAllFail(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired(), LDAPS: certUntrusted()}}
	_, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err == nil {
		t.Fatal("expected failure")
	}
	message := err.Error()
	for _, want := range []string{"LDAP 198.51.100.10:389", "LDAPS 198.51.100.10:636", "integrity checking", "certificate"} {
		if !strings.Contains(message, want) {
			t.Fatalf("diagnostic missing %q: %s", want, message)
		}
	}
}

func TestConnectNeverRepeatsATransport(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired(), LDAPS: connectivity(), StartTLS: connectivity()}}
	if _, err := (Connector{Binder: binder, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig()); err == nil {
		t.Fatal("expected failure")
	}
	seen := map[Transport]int{}
	for _, transport := range binder.calls {
		seen[transport]++
	}
	for transport, count := range seen {
		if count != 1 {
			t.Fatalf("%s was attempted %d times: %v", transport, count, binder.calls)
		}
	}
	if len(binder.calls) > 3 {
		t.Fatalf("too many attempts: %v", binder.calls)
	}
}

// Skipping verification is an explicit operator choice that travels with the
// attempt and is reported back in the session.
func TestConnectCarriesExplicitInsecureOptIn(t *testing.T) {
	options := Options{InsecureSkipVerify: true}
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired()}}
	session, err := (Connector{Binder: binder, Options: options, Resolver: &fakeResolver{}}).Connect(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("expected success with the opt-in: %v", err)
	}
	if !session.Insecure {
		t.Fatal("session did not report the opt-in")
	}
	for index, seen := range binder.options {
		if !seen.InsecureSkipVerify {
			t.Fatalf("attempt %d did not carry the opt-in: %#v", index, seen)
		}
	}
	if (Options{}).InsecureSkipVerify {
		t.Fatal("verification must be on unless the operator opts out")
	}
}

func TestClassifyFailureKinds(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		kind Kind
	}{
		"signing":       {signingRequired(), KindSigning},
		"confidential":  {&ldap.Error{ResultCode: ldap.LDAPResultConfidentialityRequired, Err: errors.New("confidentiality")}, KindSigning},
		"invalid creds": {invalidCredentials(), KindAuthentication},
		"policy":        {&ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform, Err: errors.New("policy")}, KindAuthentication},
		"mechanism":     {&ldap.Error{ResultCode: ldap.LDAPResultAuthMethodNotSupported, Err: errors.New("no such mechanism")}, KindProtocol},
		"protocol":      {&ldap.Error{ResultCode: ldap.LDAPResultProtocolError, Err: errors.New("starttls unsupported")}, KindProtocol},
		"tls":           {certUntrusted(), KindTLS},
		"handshake":     {tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, KindTLS},
		"connectivity":  {connectivity(), KindConnectivity},
		"none":          {nil, ""},
	} {
		if got := Classify(test.err); got != test.kind {
			t.Errorf("%s classified as %q, want %q", name, got, test.kind)
		}
	}
}

func TestTransportPorts(t *testing.T) {
	if LDAP.Port() != "389" || StartTLS.Port() != "389" || LDAPS.Port() != "636" {
		t.Fatalf("unexpected ports: %s/%s/%s", LDAP.Port(), StartTLS.Port(), LDAPS.Port())
	}
}

// The library wraps dial and TLS failures in its own "network error" code, so
// classification is exercised against the real client on loopback: nothing is
// listening, no packet leaves the host, and the wrapping is the library's own.
func TestClassifyRealClientLoopbackFailures(t *testing.T) {
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	binder := SystemBinder{Timeout: 300 * time.Millisecond}
	for _, transport := range []Transport{LDAP, LDAPS, StartTLS} {
		err := binder.Bind(context.Background(), cfg, transport, Options{})
		if err == nil {
			t.Fatalf("%s unexpectedly connected to loopback", transport)
		}
		if kind := Classify(err); kind != KindConnectivity {
			t.Fatalf("%s classified as %q, want %q (error: %v)", transport, kind, KindConnectivity, err)
		}
	}
}

// With every transport refused, the connector still tries each once and explains
// all of them, which is what an operator sees on an unreachable host.
func TestConnectAgainstUnreachableHostExplainsEveryTransport(t *testing.T) {
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	connector := Connector{Binder: SystemBinder{Timeout: 300 * time.Millisecond}, Resolver: &fakeResolver{}}
	_, err := connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected failure against loopback with nothing listening")
	}
	var transportErr *Error
	if !errors.As(err, &transportErr) || transportErr.Kind != KindConnectivity {
		t.Fatalf("unexpected classification: %v", err)
	}
	if len(transportErr.Attempts) != 3 {
		t.Fatalf("expected one attempt per transport, got %d: %v", len(transportErr.Attempts), err)
	}
	for _, want := range []string{"LDAP 127.0.0.1:389", "LDAPS 127.0.0.1:636", "StartTLS 127.0.0.1:389"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("diagnostic missing %q: %s", want, err)
		}
	}
}

// The operator's address stays the network destination while the certificate is
// verified against the DC name discovered for it.
func TestConnectPinsDestinationAndVerifiesDiscoveredName(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired()}}
	resolver := &fakeResolver{
		reverse: map[string][]string{"127.0.0.1": {"dc01.corp.example."}},
		forward: map[string][]string{"dc01.corp.example": {"127.0.0.1"}},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	session, err := (Connector{Binder: binder, Resolver: resolver}).Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if session.Identity.ServerName != "dc01.corp.example" || session.Identity.Source != SourceReverseDNS {
		t.Fatalf("unexpected identity: %#v", session.Identity)
	}
	if session.Endpoint != "127.0.0.1:636" || session.Transport != LDAPS {
		t.Fatalf("unexpected session: %#v", session)
	}
	for index, options := range binder.options {
		if options.TLSServerName != "dc01.corp.example" {
			t.Fatalf("attempt %d did not verify the discovered name: %#v", index, options)
		}
		if options.InsecureSkipVerify {
			t.Fatalf("attempt %d disabled verification without an opt-in", index)
		}
		if binder.targets[index] != "127.0.0.1" {
			t.Fatalf("attempt %d dialled %q instead of the operator's address", index, binder.targets[index])
		}
	}
	if len(resolver.queries) != 2 {
		t.Fatalf("discovery was not minimal: %v", resolver.queries)
	}
}

// When no name can be confirmed, the failure says so instead of inventing one,
// and credentials never appear in the diagnostic.
func TestFailureReportsUnconfirmedIdentityWithoutSecrets(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{LDAP: signingRequired(), LDAPS: certUntrusted()}}
	cfg := config.Config{Target: "198.51.100.10", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err := (Connector{Binder: binder, Resolver: &fakeResolver{reverse: map[string][]string{"198.51.100.10": {"dc01.other.example"}}}}).Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected failure")
	}
	message := err.Error()
	if !strings.Contains(message, "no TLS identity was confirmed") || !strings.Contains(message, "outside corp.example") {
		t.Fatalf("unconfirmed identity is not explained: %s", message)
	}
	if strings.Contains(message, cfg.Password) {
		t.Fatalf("diagnostic leaked the password: %s", message)
	}
}

// A host name target is verified as given, with no discovery traffic at all.
func TestConnectVerifiesHostNameTargetWithoutDiscovery(t *testing.T) {
	binder := &fakeBinder{results: map[Transport]error{}}
	resolver := &fakeResolver{}
	cfg := config.Config{Target: "dc01.corp.example", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	session, err := (Connector{Binder: binder, Resolver: resolver}).Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if session.Identity.ServerName != "dc01.corp.example" || session.Identity.Source != SourceTarget {
		t.Fatalf("unexpected identity: %#v", session.Identity)
	}
	if len(resolver.queries) != 0 {
		t.Fatalf("discovery ran for a host name target: %v", resolver.queries)
	}
}

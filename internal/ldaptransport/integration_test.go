package ldaptransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
)

// startLDAPSStub is a real TLS server reached through go-ldap's own LDAPS dial
// path. It completes the handshake and then closes, so a test can assert on the
// certificate decision without implementing an LDAP server.
func startLDAPSStub(t *testing.T, certificate tls.Certificate) (port string) {
	t.Helper()
	address := startTLSServer(t, certificate)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// This is the operator's scenario end to end: signing-required LDAP, then LDAPS
// against a controller whose certificate the host does not trust. The trust
// handler must be reached, and an approved certificate must let the handshake
// complete so the connection proceeds to the bind.
func TestLDAPSFallbackReachesTheTrustHandler(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := startLDAPSStub(t, certificate)

	trust := &recordingTrust{decision: TrustSession}
	connector := Connector{
		Binder:   SystemBinder{Timeout: 2 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: trust.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err := connector.Connect(context.Background(), cfg)

	if len(trust.calls) != 1 {
		t.Fatalf("the untrusted certificate never reached the trust handler (calls=%d, err=%v)", len(trust.calls), err)
	}
	if trust.calls[0].Identity != "dc01.corp.example" {
		t.Fatalf("the decision was not scoped to the verified identity: %#v", trust.calls[0])
	}
	if err == nil {
		t.Fatal("the stub server cannot complete an LDAP bind, so a failure was expected")
	}
	var certError *tls.CertificateVerificationError
	if errors.As(err, &certError) {
		t.Fatalf("the TLS layer still rejected an approved certificate: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "unknown authority") {
		t.Fatalf("the approved certificate was still refused: %v", err)
	}
}

// Rejecting the certificate must stop before any LDAP traffic.
func TestRejectedCertificateStopsBeforeBind(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := startLDAPSStub(t, certificate)

	trust := &recordingTrust{decision: TrustReject}
	connector := Connector{
		Binder:   SystemBinder{Timeout: 2 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: trust.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	if _, err := connector.Connect(context.Background(), cfg); err == nil {
		t.Fatal("a rejected certificate was accepted")
	}
	if len(trust.calls) != 1 {
		t.Fatalf("expected exactly one decision, got %d", len(trust.calls))
	}
}

// Without a handler the untrusted certificate stays fatal, which is what makes
// the handler's presence the difference the operator sees.
func TestWithoutHandlerTheUntrustedCertificateIsFatal(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := startLDAPSStub(t, certificate)
	connector := Connector{
		Binder:   SystemBinder{Timeout: 2 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName: "dc01.corp.example",
			Ports:         map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err := connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("an untrusted certificate was accepted without a decision")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unknown authority") {
		t.Fatalf("unexpected failure: %v", err)
	}
}

// Insecure mode must reach the TLS client and skip verification, leaving the
// connection to fail at the bind rather than at the certificate.
func TestInsecureOptInSkipsVerificationThroughTheRealDialPath(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"other.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := startLDAPSStub(t, certificate)
	connector := Connector{
		Binder:   SystemBinder{Timeout: 2 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			InsecureSkipVerify: true,
			TLSServerName:      "dc01.corp.example",
			Ports:              map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err := connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("the stub server cannot complete a bind")
	}
	if strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("insecure mode still verified the certificate: %v", err)
	}
	if Classify(err) == KindTLS {
		t.Fatalf("insecure mode still failed at TLS: %v", err)
	}
}

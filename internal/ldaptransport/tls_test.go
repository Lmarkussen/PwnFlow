package ldaptransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
)

// testCA issues short-lived certificates so certificate handling is exercised
// against a real TLS server on loopback rather than a mock.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PwnFlow test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: certificate, key: key, der: der}
}

func (ca *testCA) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// issue returns a server certificate for the supplied identities.
func (ca *testCA) issue(t *testing.T, dnsNames []string, addresses []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	return ca.issueWithUsages(t, dnsNames, addresses, notBefore, notAfter, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// issueWithUsages returns a certificate with explicit extended key usages.
func (ca *testCA) issueWithUsages(t *testing.T, dnsNames []string, addresses []net.IP, notBefore, notAfter time.Time, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "domain controller"},
		DNSNames:     dnsNames,
		IPAddresses:  addresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}
}

// startTLSServer performs real handshakes on loopback and then closes, so a test
// can assert on the certificate check alone without an LDAP server.
func startTLSServer(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.HandshakeContext(context.Background())
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// dialWithVerification performs a real TLS handshake using the verification the
// binder would apply for this target.
func dialWithVerification(t *testing.T, address string, cfg config.Config, options Options) error {
	t.Helper()
	verification := newTLSVerification(cfg, options)
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, verification.config)
	if err != nil {
		return wrapTLSFailure(err, verification.serverName, cfg.Target)
	}
	_ = connection.Close()
	return nil
}

// A certificate carrying the discovered DC name is accepted even though the
// connection itself is made to an address, which is the operator's case.
func TestDiscoveredNameSatisfiesCertificateWithDNSNameOnly(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	options := Options{TLSServerName: "dc01.corp.example", RootCAs: ca.pool(t)}
	if err := dialWithVerification(t, address, cfg, options); err != nil {
		t.Fatalf("DNS-named certificate was rejected: %v", err)
	}
}

// Without a discovered name the address is verified, and a DNS-only certificate
// is reported as the IP SAN problem it is - pointing at discovery, not at trust.
func TestAddressVerificationReportsMissingIPSAN(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	err := dialWithVerification(t, address, cfg, Options{RootCAs: ca.pool(t)})
	if err == nil {
		t.Fatal("a certificate without an IP SAN was accepted for an address target")
	}
	if !strings.Contains(err.Error(), "no IP SAN for 127.0.0.1") || !strings.Contains(err.Error(), "no DNS name for that address could be confirmed") {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
	if Classify(err) != KindTLS {
		t.Fatalf("unexpected kind: %v", err)
	}
}

func TestUntrustedIssuerIsReported(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example"})
	if err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	if !strings.Contains(err.Error(), "not in the trust store") {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
	if Classify(err) != KindTLS {
		t.Fatalf("unexpected kind: %v", err)
	}
}

func TestExpiredCertificateIsReported(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example", RootCAs: ca.pool(t)})
	if err == nil {
		t.Fatal("an expired certificate was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
}

func TestMismatchedCertificateNameIsReported(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"other.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example", RootCAs: ca.pool(t)})
	if err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	if !strings.Contains(err.Error(), `not valid for "dc01.corp.example"`) {
		t.Fatalf("diagnostic does not name the identity under verification: %v", err)
	}
}

// The explicit opt-in is the only way verification is skipped, and it is reported.
func TestExplicitOptInSkipsVerificationOnlyWhenAsked(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"other.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	if err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example", InsecureSkipVerify: true}); err != nil {
		t.Fatalf("the explicit opt-in did not allow the connection: %v", err)
	}
	session, err := (Connector{
		Binder:   &fakeBinder{results: map[Transport]error{LDAP: signingRequired()}},
		Options:  Options{InsecureSkipVerify: true},
		Resolver: &fakeResolver{},
	}).Connect(context.Background(), config.Config{Target: "198.51.100.10", Domain: "corp.example"})
	if err != nil {
		t.Fatalf("opt-in session failed: %v", err)
	}
	if !session.Insecure {
		t.Fatal("the opt-in was not reported in the session")
	}
}

// Discovery alone never weakens verification: a session that used no opt-in
// still fails against a certificate it cannot trust.
func TestDiscoveryNeverSkipsVerification(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	options := Options{TLSServerName: "dc01.corp.example"}
	if options.InsecureSkipVerify {
		t.Fatal("verification was disabled without an operator opt-in")
	}
	if err := dialWithVerification(t, address, cfg, options); err == nil {
		t.Fatal("an untrusted chain was accepted although verification was on")
	}
}

// errors.As still reaches the certificate cause through the added explanation.
func TestExplainedFailureRemainsClassifiable(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example"}
	err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example"})
	if err == nil {
		t.Fatal("expected failure")
	}
	var unknownAuthority x509.UnknownAuthorityError
	var verificationError *tls.CertificateVerificationError
	if !errors.As(err, &unknownAuthority) && !errors.As(err, &verificationError) {
		t.Fatalf("certificate cause was lost: %v", err)
	}
	if Classify(err) != KindTLS {
		t.Fatalf("unexpected kind: %v", err)
	}
}

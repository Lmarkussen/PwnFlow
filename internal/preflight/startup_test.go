package preflight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/trust"
)

// These tests drive the startup path the operator actually runs - preflight.Run
// with the real LDAP client, the real certificate decision, and a real TLS
// server on loopback - so the certificate prompt is proven to appear (or not) in
// the wiring the operator uses, not only in a certificate verifier in isolation.

// startupCA issues certificates from an authority the host does not trust.
type startupCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newStartupCA(t *testing.T) *startupCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lab Issuing CA"},
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
	return &startupCA{cert: certificate, key: key}
}

func (ca *startupCA) issue(t *testing.T, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// bindStub is a TLS LDAP server that answers every bind with success and counts
// the bind requests it received, so a test can prove whether the connection got
// as far as the bind.
type bindStub struct {
	listener net.Listener
	binds    atomic.Int64
}

func startBindStub(t *testing.T, certificate tls.Certificate) *bindStub {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	stub := &bindStub{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go stub.serve(connection)
		}
	}()
	return stub
}

func (s *bindStub) serve(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	for {
		body, err := readLDAPMessage(connection)
		if err != nil {
			return
		}
		messageID, err := readMessageID(body)
		if err != nil {
			return
		}
		s.binds.Add(1)
		if _, err := connection.Write(bindSuccess(messageID)); err != nil {
			return
		}
	}
}

func (s *bindStub) bindCount() int { return int(s.binds.Load()) }

func (s *bindStub) port(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// readLDAPMessage reads one BER-encoded LDAP message and returns its contents.
func readLDAPMessage(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, errors.New("unexpected BER tag")
	}
	size := int(header[1])
	if size&0x80 != 0 {
		lengthBytes := size & 0x7f
		if lengthBytes == 0 || lengthBytes > 4 {
			return nil, errors.New("unsupported BER length")
		}
		encoded := make([]byte, lengthBytes)
		if _, err := io.ReadFull(reader, encoded); err != nil {
			return nil, err
		}
		size = 0
		for _, value := range encoded {
			size = size<<8 | int(value)
		}
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func readMessageID(body []byte) (int, error) {
	if len(body) < 2 || body[0] != 0x02 {
		return 0, errors.New("unexpected message shape")
	}
	length := int(body[1])
	if length < 1 || length > 4 || 2+length > len(body) {
		return 0, errors.New("unexpected message id length")
	}
	messageID := 0
	for _, value := range body[2 : 2+length] {
		messageID = messageID<<8 | int(value)
	}
	return messageID, nil
}

// bindSuccess encodes a BindResponse with result code 0.
func bindSuccess(messageID int) []byte {
	encodedID := encodeInteger(messageID)
	result := []byte{0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	inner := []byte{0x02, byte(len(encodedID))}
	inner = append(inner, encodedID...)
	inner = append(inner, 0x61, byte(len(result)))
	inner = append(inner, result...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

func encodeInteger(value int) []byte {
	encoded := []byte{}
	for value > 0 {
		encoded = append([]byte{byte(value & 0xff)}, encoded...)
		value >>= 8
	}
	if len(encoded) == 0 {
		encoded = []byte{0}
	}
	if encoded[0]&0x80 != 0 {
		encoded = append([]byte{0}, encoded...)
	}
	return encoded
}

// fakeNXC satisfies the preflight dependency check without a real NetExec.
func fakeNXC(t *testing.T) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "nxc"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
}

func scriptedDecider(input string, store *trust.Store) (*trust.Decider, *strings.Builder) {
	output := &strings.Builder{}
	return &trust.Decider{Store: store, In: strings.NewReader(input), Out: output, Interactive: func() bool { return true }}, output
}

func startupConfig() config.Config {
	return config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
}

// approvedOptions is what main builds once the address has been resolved to the
// controller's DNS name: the identity under verification, the decision, and the
// port the local test server listens on.
func approvedOptions(t *testing.T, stub *bindStub, identity string, decider *trust.Decider) ldaptransport.Options {
	t.Helper()
	return ldaptransport.Options{
		TLSServerName:    identity,
		CertificateTrust: decider.Decide,
		Ports:            map[ldaptransport.Transport]string{ldaptransport.LDAPS: stub.port(t)},
	}
}

// The operator's scenario: signing-required LDAP, then LDAPS against a controller
// whose authority the host does not trust. The prompt must appear, and the
// approval must carry the same connection through to a successful bind.
func TestStartupPromptUnlocksTheUntrustedCertificate(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))
	decider, output := scriptedDecider("s\n", nil)

	cfg := startupConfig()
	result, err := Run(context.Background(), cfg, approvedOptions(t, stub, "dc01.corp.example", decider))
	if err != nil {
		t.Fatalf("an approved certificate did not reach the bind: %v", err)
	}
	if result.Transport != ldaptransport.LDAPS {
		t.Fatalf("unexpected transport: %#v", result)
	}
	if stub.bindCount() == 0 {
		t.Fatal("the approved connection never reached the bind")
	}
	for _, wanted := range []string{
		"dc01.corp.example",
		"Lab Issuing CA",
		"SHA-256",
		"[t] trust and remember",
		"[s] accept this certificate for this session only",
		"[r] reject and exit",
	} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("the prompt never showed %q:\n%s", wanted, output.String())
		}
	}
	if strings.Contains(output.String(), cfg.Password) {
		t.Fatalf("the prompt leaked the password:\n%s", output.String())
	}
}

// A rejected certificate must stop the connection before any bind is offered.
func TestStartupRejectionStopsBeforeTheBind(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))
	decider, output := scriptedDecider("r\n", nil)

	_, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", decider))
	if err == nil {
		t.Fatal("a rejected certificate still produced a session")
	}
	if !strings.Contains(output.String(), "not trusted") {
		t.Fatalf("the operator was never asked:\n%s", output.String())
	}
	if stub.bindCount() != 0 {
		t.Fatalf("a rejected certificate still offered %d bind(s)", stub.bindCount())
	}
	if ClassifyBindError(err) != FailureTLS {
		t.Fatalf("unexpected failure kind: %v", err)
	}
}

// An empty answer is not an answer: the default has to be refusal.
func TestStartupEmptyAnswerIsNotAcceptance(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))
	decider, _ := scriptedDecider("\n", nil)

	if _, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", decider)); err == nil {
		t.Fatal("an empty answer accepted the certificate")
	}
	if stub.bindCount() != 0 {
		t.Fatalf("an unanswered prompt still offered %d bind(s)", stub.bindCount())
	}
}

// The explicit opt-in must reach the TLS client: with it the connection skips
// verification, is reported as insecure, and proceeds to the bind without ever
// asking the operator.
func TestStartupInsecureOptInSkipsVerificationAndReachesTheBind(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))
	decider, output := scriptedDecider("r\n", nil)

	cfg := startupConfig()
	cfg.InsecureSkipVerify = true
	options := approvedOptions(t, stub, "dc01.corp.example", decider)
	options.InsecureSkipVerify = cfg.InsecureSkipVerify
	result, err := Run(context.Background(), cfg, options)
	if err != nil {
		t.Fatalf("--insecure-skip-verify did not reach the TLS client: %v", err)
	}
	if !result.Insecure {
		t.Fatal("the session does not report that verification was skipped")
	}
	if stub.bindCount() == 0 {
		t.Fatal("the opted-in connection never reached the bind")
	}
	if strings.Contains(output.String(), "not trusted") {
		t.Fatalf("verification was skipped but the operator was still asked:\n%s", output.String())
	}
}

// A certificate that names a different host must stay fatal: the trust decision
// only ever answers the issuing-authority question.
func TestStartupWrongHostnameCannotBeApproved(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"other.example"}))
	decider, output := scriptedDecider("s\n", nil)

	_, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", decider))
	if err == nil {
		t.Fatal("a certificate for the wrong host was accepted")
	}
	if strings.Contains(output.String(), "not trusted") {
		t.Fatalf("a name mismatch was offered as a decision:\n%s", output.String())
	}
	if ClassifyBindError(err) != FailureTLS {
		t.Fatalf("unexpected failure kind: %v", err)
	}
	if stub.bindCount() != 0 {
		t.Fatalf("a wrong-host certificate still offered %d bind(s)", stub.bindCount())
	}
}

// An address target whose certificate carries no matching IP SAN cannot be
// approved either, and the failure has to say why rather than looking like an
// authentication problem.
func TestStartupAddressWithoutIPSANIsExplained(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))
	decider, _ := scriptedDecider("s\n", nil)

	options := ldaptransport.Options{
		CertificateTrust: decider.Decide,
		Ports:            map[ldaptransport.Transport]string{ldaptransport.LDAPS: stub.port(t)},
	}
	_, err := Run(context.Background(), startupConfig(), options)
	if err == nil {
		t.Fatal("a certificate without a matching IP SAN was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ip san") {
		t.Fatalf("the failure does not explain the certificate identity problem: %v", err)
	}
	if stub.bindCount() != 0 {
		t.Fatalf("an unverifiable certificate still offered %d bind(s)", stub.bindCount())
	}
}

// Trusting a certificate for later runs has to work from the startup path, and
// the stored approval must stay free of credentials.
func TestStartupRememberedApprovalSkipsTheNextPrompt(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))

	path := filepath.Join(t.TempDir(), "pwnflow", "trusted-certificates.json")
	store, err := trust.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	firstDecider, firstOutput := scriptedDecider("t\n", store)
	result, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", firstDecider))
	if err != nil {
		t.Fatalf("storing the approval failed the run: %v", err)
	}
	if result.Transport != ldaptransport.LDAPS {
		t.Fatalf("unexpected transport: %#v", result)
	}
	if !strings.Contains(firstOutput.String(), "approved for dc01.corp.example") {
		t.Fatalf("the approval was not recorded:\n%s", firstOutput.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("the approval store is readable by others: %o", permissions)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), startupConfig().Password) {
		t.Fatal("the approval store contains the password")
	}

	reloaded, err := trust.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	nextDecider, nextOutput := scriptedDecider("", reloaded)
	if _, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", nextDecider)); err != nil {
		t.Fatalf("the remembered approval was not honoured: %v", err)
	}
	if !strings.Contains(nextOutput.String(), "matches the stored approval") {
		t.Fatalf("the second run did not use the stored approval:\n%s", nextOutput.String())
	}
}

// A controller that presents a different certificate than the approved one has
// to be decided again: an existing approval is for one exact certificate.
func TestStartupChangedCertificateRequiresANewDecision(t *testing.T) {
	fakeNXC(t)
	ca := newStartupCA(t)
	stub := startBindStub(t, ca.issue(t, []string{"dc01.corp.example"}))

	path := filepath.Join(t.TempDir(), "pwnflow", "trusted-certificates.json")
	store, err := trust.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(trust.Record{
		Target:      startupConfig().Target,
		Identity:    "dc01.corp.example",
		Fingerprint: "00:11:22:33",
		NotAfter:    time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	decider, output := scriptedDecider("", store)
	if _, err := Run(context.Background(), startupConfig(), approvedOptions(t, stub, "dc01.corp.example", decider)); err == nil {
		t.Fatal("a changed certificate was accepted from the stored approval")
	}
	if !strings.Contains(output.String(), "differs from the stored approval") {
		t.Fatalf("the changed certificate was not raised with the operator:\n%s", output.String())
	}
	if stub.bindCount() != 0 {
		t.Fatalf("a changed certificate still offered %d bind(s)", stub.bindCount())
	}
}

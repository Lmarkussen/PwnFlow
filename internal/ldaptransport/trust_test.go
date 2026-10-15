package ldaptransport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
)

// recordingTrust answers with a fixed decision and remembers what it was asked,
// so tests can prove a decision is only requested when it is allowed.
type recordingTrust struct {
	decision TrustDecision
	calls    []CertificateInfo
}

func (r *recordingTrust) handler() TrustHandler {
	return func(info CertificateInfo) (TrustDecision, error) {
		r.calls = append(r.calls, info)
		return r.decision, nil
	}
}

func fingerprintOf(certificate tls.Certificate) string {
	digest := sha256.Sum256(certificate.Certificate[0])
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

// A certificate the host trusts never reaches a trust decision.
func TestTrustedCertificateNeedsNoDecision(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	trust := &recordingTrust{decision: TrustReject}
	err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{
		TLSServerName:    "dc01.corp.example",
		RootCAs:          ca.pool(t),
		CertificateTrust: trust.handler(),
	})
	if err != nil {
		t.Fatalf("trusted certificate was rejected: %v", err)
	}
	if len(trust.calls) != 0 {
		t.Fatalf("a trust decision was requested for a trusted certificate: %#v", trust.calls)
	}
}

// An unknown issuing authority is the one case the operator may decide.
func TestUntrustedAuthorityOffersTheDecision(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startTLSServer(t, certificate)
	trust := &recordingTrust{decision: TrustSession}
	err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{
		TLSServerName:    "dc01.corp.example",
		CertificateTrust: trust.handler(),
	})
	if err != nil {
		t.Fatalf("an accepted certificate still failed: %v", err)
	}
	if len(trust.calls) != 1 {
		t.Fatalf("expected exactly one decision request, got %d", len(trust.calls))
	}
	info := trust.calls[0]
	if info.Identity != "dc01.corp.example" || info.Target != "127.0.0.1" {
		t.Fatalf("decision was not scoped correctly: %#v", info)
	}
	if info.Issuer == "" || info.Subject == "" || info.NotAfter.IsZero() {
		t.Fatalf("decision lacks certificate details: %#v", info)
	}
	if info.Fingerprint == "" || len(info.Fingerprint) < 32 {
		t.Fatalf("decision lacks a usable fingerprint: %q", info.Fingerprint)
	}
	if !strings.Contains(strings.ToLower(info.Reason), "unknown authority") {
		t.Fatalf("decision does not explain the problem: %q", info.Reason)
	}
}

func TestRejectedAuthorityStopsTheConnection(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	trust := &recordingTrust{decision: TrustReject}
	err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{
		TLSServerName:    "dc01.corp.example",
		CertificateTrust: trust.handler(),
	})
	if err == nil {
		t.Fatal("a rejected certificate was accepted")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
}

// Without a handler the unknown authority stays fatal: there is nothing to ask.
func TestUntrustedAuthorityWithoutHandlerFails(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{TLSServerName: "dc01.corp.example"})
	if err == nil {
		t.Fatal("an untrusted certificate was accepted without a decision")
	}
	if Classify(err) != KindTLS {
		t.Fatalf("unexpected kind: %v", err)
	}
}

// Everything except the issuing authority must already hold: an expired or
// wrongly named certificate can never be talked into acceptance.
func TestBadCertificatesCannotBeAccepted(t *testing.T) {
	for name, certificate := range map[string]tls.Certificate{
		"expired":    newTestCA(t).issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)),
		"wrong name": newTestCA(t).issue(t, []string{"other.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t)
			_ = ca
			address := startTLSServer(t, certificate)
			trust := &recordingTrust{decision: TrustPersist}
			err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{
				TLSServerName:    "dc01.corp.example",
				CertificateTrust: trust.handler(),
			})
			if err == nil {
				t.Fatal("a bad certificate was accepted")
			}
			if len(trust.calls) != 0 {
				t.Fatalf("a decision was requested for a certificate that is invalid for another reason: %#v", trust.calls)
			}
		})
	}
}

// A certificate that is not usable for server authentication is invalid for
// another reason, and is never offered as a trust decision.
func TestClientOnlyCertificateIsNotOffered(t *testing.T) {
	ca := newTestCA(t)
	// A certificate that is only meant for client authentication is invalid for
	// another reason, so it must never reach the operator as a trust decision.
	issued := ca.issueWithUsages(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	trust := &recordingTrust{decision: TrustPersist}
	if err := verifyPresentedCertificate([][]byte{issued.Certificate[0]}, "dc01.corp.example", config.Config{Target: "127.0.0.1"}, Options{CertificateTrust: trust.handler()}); err == nil {
		t.Fatal("a client-only certificate was accepted")
	}
	if len(trust.calls) != 0 {
		t.Fatalf("a decision was requested for a client-only certificate: %#v", trust.calls)
	}
}

// The decision itself never carries credentials.
func TestCertificateDecisionCarriesNoSecrets(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	trust := &recordingTrust{decision: TrustSession}
	if err := dialWithVerification(t, address, cfg, Options{TLSServerName: "dc01.corp.example", CertificateTrust: trust.handler()}); err != nil {
		t.Fatalf("accepted certificate failed: %v", err)
	}
	for _, info := range trust.calls {
		rendered := info.Subject + info.Issuer + info.Fingerprint + info.Reason
		if strings.Contains(rendered, cfg.Password) {
			t.Fatalf("decision metadata contains the password: %q", rendered)
		}
	}
}

// The explained failure stays classifiable and reachable through errors.As.
func TestVerificationFailureStillUnwrapsToCertificateError(t *testing.T) {
	ca := newTestCA(t)
	address := startTLSServer(t, ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	err := dialWithVerification(t, address, config.Config{Target: "127.0.0.1", Domain: "corp.example"}, Options{TLSServerName: "dc01.corp.example"})
	if err == nil {
		t.Fatal("expected failure")
	}
	var unknownAuthority x509.UnknownAuthorityError
	var verificationError *tls.CertificateVerificationError
	if !errors.As(err, &unknownAuthority) && !errors.As(err, &verificationError) {
		t.Fatalf("certificate cause was lost: %v", err)
	}
	if net.ParseIP("127.0.0.1") == nil {
		t.Fatal("unreachable")
	}
}

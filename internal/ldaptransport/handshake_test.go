package ldaptransport

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
)

// slowTrust answers a certificate decision after a delay, the way an operator
// does after reading the subject, issuer, and fingerprint.
type slowTrust struct {
	delay    time.Duration
	decision TrustDecision

	mutex sync.Mutex
	calls int
}

func (s *slowTrust) handler() TrustHandler {
	return func(CertificateInfo) (TrustDecision, error) {
		time.Sleep(s.delay)
		s.mutex.Lock()
		s.calls++
		s.mutex.Unlock()
		return s.decision, nil
	}
}

// A certificate decision is answered by a person inside the TLS handshake. The
// dial timeout must not close the connection while that decision is still being
// made, or the operator approves a certificate that never reaches the bind.
// This is the regression that failed before the LDAPS dial stopped passing the
// dial timeout to the handshake as a deadline.
func TestSlowTrustDecisionIsNotCutOffByTheDialTimeout(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startBindStub(t, certificate, map[string]bool{"audituser@corp.example": true})
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	decision := &slowTrust{delay: 900 * time.Millisecond, decision: TrustSession}
	connector := Connector{
		// The dial bound is far shorter than the operator's decision, which is the
		// situation a real operator is in whenever the prompt needs reading.
		Binder:   SystemBinder{Timeout: 250 * time.Millisecond},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: decision.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	session, err := connector.Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the approved certificate did not reach the bind: %v", err)
	}
	if session.Transport != LDAPS {
		t.Fatalf("unexpected transport: %#v", session)
	}
	if decision.calls != 1 {
		t.Fatalf("expected one decision, got %d", decision.calls)
	}
}

// The handshake bound has to leave room for a person, and it must stay finite so
// an unresponsive server cannot hold startup open.
func TestHandshakeTimeoutLeavesRoomForADecision(t *testing.T) {
	dialTimeout := 5 * time.Second
	withDecision := handshakeTimeout(dialTimeout, Options{CertificateTrust: func(CertificateInfo) (TrustDecision, error) {
		return TrustReject, nil
	}})
	if withDecision <= dialTimeout {
		t.Fatalf("a certificate decision is raced by the dial timeout: %s", withDecision)
	}
	if withDecision > 30*time.Minute {
		t.Fatalf("the handshake bound is not finite in practice: %s", withDecision)
	}
	if got := handshakeTimeout(dialTimeout, Options{}); got != dialTimeout {
		t.Fatalf("without a decision the dial timeout must be used: %s", got)
	}
}

// The version of the certificate under verification is what a rejection must
// report, so a rejected decision can never look like a TLS protocol failure the
// operator would try to retry.
func TestRejectedDecisionReportsTheDecision(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startBindStub(t, certificate, map[string]bool{"audituser@corp.example": true})
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	connector := Connector{
		Binder:   SystemBinder{Timeout: 2 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: (&slowTrust{decision: TrustReject}).handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err = connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("a rejected certificate still produced a session")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("the rejection was not reported as a decision: %v", err)
	}
	if strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("the rejection was reported as an untrusted authority instead: %v", err)
	}
}

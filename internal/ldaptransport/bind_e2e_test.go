package ldaptransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
)

// startBindStub is the smallest LDAP-over-TLS server that can answer a bind: it
// refuses the SASL (NTLM) exchange and answers a simple bind according to the
// accepted identities. That mirrors a controller which rejects NTLM but accepts
// a simple bind over the TLS channel.
func startBindStub(t *testing.T, certificate tls.Certificate, accepted map[string]bool) string {
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
			go serveBindStub(connection, accepted)
		}
	}()
	return listener.Addr().String()
}

func serveBindStub(connection net.Conn, accepted map[string]bool) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(connection, header); err != nil {
			return
		}
		if header[0] != 0x30 || header[1] == 0 || header[1]&0x80 != 0 {
			return
		}
		body := make([]byte, int(header[1]))
		if _, err := io.ReadFull(connection, body); err != nil {
			return
		}
		if len(body) < 5 || body[0] != 0x02 || body[1] != 0x01 {
			return
		}
		messageID := body[2]
		if index := indexOfByte(body, 0xa3); index >= 0 {
			// SASL bind (NTLM): this controller refuses the mechanism.
			if _, err := connection.Write(bindResponse(messageID, 7)); err != nil {
				return
			}
			continue
		}
		identity := simpleBindIdentity(body)
		code := byte(49)
		if accepted[strings.ToLower(identity)] {
			code = 0
		}
		if _, err := connection.Write(bindResponse(messageID, code)); err != nil {
			return
		}
	}
}

func indexOfByte(body []byte, wanted byte) int {
	for index, value := range body {
		if value == wanted {
			return index
		}
	}
	return -1
}

// simpleBindIdentity returns the bind name, which is the first OCTET STRING after
// the version in a BindRequest.
func simpleBindIdentity(body []byte) string {
	for index := 3; index+1 < len(body); index++ {
		if body[index] == 0x04 {
			length := int(body[index+1])
			if index+2+length <= len(body) {
				return strings.TrimSpace(string(body[index+2 : index+2+length]))
			}
			return ""
		}
	}
	return ""
}

// bindResponse encodes a BindResponse with the given result code, following
// LDAP's structure: SEQUENCE { INTEGER messageID, [APPLICATION 1] SEQUENCE {
// ENUMERATED resultCode, OCTET matchedDN, OCTET diagnosticMessage } }.
func bindResponse(messageID, code byte) []byte {
	return []byte{0x30, 0x0c, 0x02, 0x01, messageID, 0x61, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00}
}

func TestConnectBindsAfterTrustApproval(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startBindStub(t, certificate, map[string]bool{"audituser@corp.example": true})
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	trust := &recordingTrust{decision: TrustSession}
	connector := Connector{
		Binder:   SystemBinder{Timeout: 3 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: trust.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	session, err := connector.Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("approved certificate did not lead to a successful bind: %v", err)
	}
	if session.Transport != LDAPS {
		t.Fatalf("unexpected transport: %#v", session)
	}
	if len(trust.calls) != 1 {
		t.Fatalf("expected one trust decision, got %d", len(trust.calls))
	}
	if session.Identity.ServerName != "dc01.corp.example" {
		t.Fatalf("unexpected identity: %#v", session.Identity)
	}
}

// Rejecting the certificate must stop before any bind reaches the controller.
func TestConnectStopsBeforeBindWhenCertificateIsRejected(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startBindStub(t, certificate, map[string]bool{"audituser@corp.example": true})
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	trust := &recordingTrust{decision: TrustReject}
	connector := Connector{
		Binder:   SystemBinder{Timeout: 3 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: trust.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err = connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("a rejected certificate still produced a session")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unexpected failure: %v", err)
	}
}

// Wrong credentials over an approved channel must be reported as an
// authentication failure, not as a certificate or transport problem.
func TestConnectReportsRejectedCredentialsAfterApproval(t *testing.T) {
	ca := newTestCA(t)
	certificate := ca.issue(t, []string{"dc01.corp.example"}, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	address := startBindStub(t, certificate, map[string]bool{"someone-else@corp.example": true})
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	trust := &recordingTrust{decision: TrustSession}
	connector := Connector{
		Binder:   SystemBinder{Timeout: 3 * time.Second},
		Resolver: &fakeResolver{},
		Options: Options{
			TLSServerName:    "dc01.corp.example",
			CertificateTrust: trust.handler(),
			Ports:            map[Transport]string{LDAPS: port},
		},
	}
	cfg := config.Config{Target: "127.0.0.1", Domain: "corp.example", Username: "audituser", Password: "Sup3rSecret"}
	_, err = connector.Connect(context.Background(), cfg)
	if err == nil {
		t.Fatal("a rejected credential produced a session")
	}
	if Classify(err) != KindAuthentication {
		t.Fatalf("classified as %q: %v", Classify(err), err)
	}
	if strings.Contains(err.Error(), cfg.Password) {
		t.Fatalf("diagnostic leaked the password: %v", err)
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		t.Fatalf("authentication failure was reported as a certificate problem: %v", err)
	}
}

// Package ldaptransport decides how PwnFlow's own LDAP connections are protected
// and performs the NTLM bind for them.
//
// Active Directory domains may require LDAP signing/integrity, which an unsigned
// NTLM bind over plain LDAP cannot satisfy: the server answers result code 8
// (strongerAuthRequired). The connector therefore tries plain LDAP first and,
// when the server demands integrity or the plain endpoint cannot be reached,
// retries the same credentials over LDAPS. StartTLS is attempted only when LDAPS
// itself is unreachable, which is the case where the 389 path is the only one
// left. Authentication failures are never retried: the credentials are wrong, not
// the transport. External tools are deliberately out of scope here - they have
// their own transport flags and their own failure reporting.
package ldaptransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
)

// Transport names one way of protecting the LDAP connection.
type Transport string

const (
	LDAP     Transport = "LDAP"
	LDAPS    Transport = "LDAPS"
	StartTLS Transport = "StartTLS"
)

// Port is the TCP port the transport uses.
func (t Transport) Port() string {
	if t == LDAPS {
		return "636"
	}
	return "389"
}

// Kind classifies why an attempt failed. The distinctions are kept separate so a
// signing requirement is never reported as bad credentials, and a trust problem
// is never reported as an unreachable host.
type Kind string

const (
	KindAuthentication Kind = "authentication"
	KindSigning        Kind = "signing"
	KindTLS            Kind = "tls"
	KindConnectivity   Kind = "connectivity"
	KindProtocol       Kind = "protocol"
)

// Attempt records one transport attempt and how it ended.
type Attempt struct {
	Transport Transport
	Endpoint  string
	Kind      Kind
	Err       error
}

// Session reports the transport that carried a successful bind.
type Session struct {
	Transport Transport
	Endpoint  string
	Insecure  bool
}

// Error aggregates every attempt that was made, so a failure explains each
// transport rather than only the last one.
type Error struct {
	Attempts []Attempt
	Kind     Kind
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Attempts))
	for _, attempt := range e.Attempts {
		parts = append(parts, fmt.Sprintf("%s %s: %v", attempt.Transport, attempt.Endpoint, attempt.Err))
	}
	return fmt.Sprintf("no LDAP transport succeeded (%s)", strings.Join(parts, "; "))
}

// Unwrap exposes the last attempt's error for errors.As/Is callers.
func (e *Error) Unwrap() error {
	if len(e.Attempts) == 0 {
		return nil
	}
	return e.Attempts[len(e.Attempts)-1].Err
}

// Options carries the explicit TLS opt-in. Verification is on unless the
// operator asked for it to be skipped; nothing here disables it silently.
type Options struct {
	InsecureSkipVerify bool
}

// Binder performs one NTLM bind over one transport. It is an interface so the
// transport policy can be exercised without a domain controller.
type Binder interface {
	Bind(ctx context.Context, cfg config.Config, transport Transport, options Options) error
}

// Connector applies the transport policy.
type Connector struct {
	Binder  Binder
	Options Options
}

// Connect binds with the configured credentials, following the fallback policy.
// It stops as soon as a transport succeeds, and it never retries credentials the
// server refused.
func (c Connector) Connect(ctx context.Context, cfg config.Config) (Session, error) {
	binder := c.Binder
	if binder == nil {
		binder = SystemBinder{}
	}
	attempts := make([]Attempt, 0, 3)
	attempt := func(transport Transport) bool {
		endpoint := net.JoinHostPort(cfg.Target, transport.Port())
		err := binder.Bind(ctx, cfg, transport, c.Options)
		if err == nil {
			attempts = append(attempts, Attempt{Transport: transport, Endpoint: endpoint})
			return true
		}
		attempts = append(attempts, Attempt{Transport: transport, Endpoint: endpoint, Kind: Classify(err), Err: err})
		return false
	}
	last := func() Attempt { return attempts[len(attempts)-1] }

	// 1. Plain LDAP, exactly as before: it is still the cheapest path and it is
	// what a domain without a signing requirement answers to.
	if attempt(LDAP) {
		return sessionFor(attempts, c.Options), nil
	}
	switch last().Kind {
	case KindAuthentication, KindTLS, KindProtocol:
		// Wrong credentials; a trust problem another transport would hit too; or a
		// server that refuses the bind mechanism entirely. Retrying would either
		// repeat invalid credentials or change nothing.
		return Session{}, &Error{Attempts: attempts, Kind: last().Kind}
	}

	// 2. LDAPS: a TLS channel satisfies integrity checking, so the same
	// credentials bind where the plain connection was refused.
	if attempt(LDAPS) {
		return sessionFor(attempts, c.Options), nil
	}
	switch last().Kind {
	case KindAuthentication, KindTLS, KindProtocol, KindSigning:
		return Session{}, &Error{Attempts: attempts, Kind: last().Kind}
	}

	// 3. StartTLS on 389, only because LDAPS could not be reached at all.
	if attempt(StartTLS) {
		return sessionFor(attempts, c.Options), nil
	}
	return Session{}, &Error{Attempts: attempts, Kind: last().Kind}
}

func sessionFor(attempts []Attempt, options Options) Session {
	successful := attempts[len(attempts)-1]
	return Session{Transport: successful.Transport, Endpoint: successful.Endpoint, Insecure: options.InsecureSkipVerify}
}

// Classify maps a bind error onto the failure kind that describes it.
func Classify(err error) Kind {
	if err == nil {
		return ""
	}
	// The concrete cause is inspected first: go-ldap reports both an unreachable
	// host and a failed TLS handshake with its own "network error" code, so the
	// result code alone cannot tell a trust problem from a closed port.
	if kind, ok := classifyCause(err); ok {
		return kind
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) && ldapErr.ResultCode != 0 {
		switch ldapErr.ResultCode {
		case ldap.ErrorNetwork:
			return KindConnectivity
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return KindSigning
		case ldap.LDAPResultAuthMethodNotSupported, ldap.LDAPResultInappropriateAuthentication, ldap.LDAPResultProtocolError:
			return KindProtocol
		}
		// Any other server answer means the credentials were offered and refused,
		// or the operation was rejected for an account/policy reason.
		return KindAuthentication
	}
	return KindConnectivity
}

// classifyCause looks for the concrete network or TLS cause behind the LDAP
// wrapping. The text check covers the one path where go-ldap formats the cause
// into the message instead of wrapping it (a StartTLS handshake failure).
func classifyCause(err error) (Kind, bool) {
	var verificationError *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError
	switch {
	case errors.As(err, &verificationError),
		errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameError),
		errors.As(err, &invalidCertificate),
		errors.As(err, &recordHeader):
		return KindTLS, true
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "tls handshake failed") || strings.Contains(message, "x509:") || strings.Contains(message, "certificate") {
		return KindTLS, true
	}
	var operationError *net.OpError
	var dnsError *net.DNSError
	if errors.As(err, &operationError) || errors.As(err, &dnsError) {
		return KindConnectivity, true
	}
	return "", false
}

// SystemBinder performs the bind with the go-ldap client PwnFlow already uses.
type SystemBinder struct {
	// Timeout bounds dialing and the TLS handshake; it defaults to five seconds.
	Timeout time.Duration
}

func (b SystemBinder) timeout() time.Duration {
	if b.Timeout > 0 {
		return b.Timeout
	}
	return 5 * time.Second
}

// Bind connects using the requested transport and performs the NTLM bind.
func (b SystemBinder) Bind(ctx context.Context, cfg config.Config, transport Transport, options Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := b.timeout()
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{ServerName: cfg.Target, InsecureSkipVerify: options.InsecureSkipVerify} // #nosec G402 -- explicit operator opt-in, off by default
	address := net.JoinHostPort(cfg.Target, transport.Port())

	var (
		client *ldap.Conn
		err    error
	)
	switch transport {
	case LDAPS:
		client, err = ldap.DialURL("ldaps://"+address, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
	default:
		client, err = ldap.DialURL("ldap://"+address, ldap.DialWithDialer(dialer))
	}
	if err != nil {
		return err
	}
	defer client.Close()
	client.SetTimeout(timeout)
	if transport == StartTLS {
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	return client.NTLMBind(cfg.Domain, cfg.Username, cfg.Password)
}

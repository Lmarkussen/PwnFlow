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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

// PortFor reports the port to dial, honouring an override when one is set.
func (t Transport) PortFor(options Options) string {
	if port := strings.TrimSpace(options.Ports[t]); port != "" {
		return port
	}
	return t.Port()
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
	Identity  Identity
}

// Error aggregates every attempt that was made, so a failure explains each
// transport rather than only the last one.
type Error struct {
	Attempts []Attempt
	Kind     Kind
	Identity Identity
}

func (e *Error) Error() string {
	parts := make([]string, 0, len(e.Attempts))
	for _, attempt := range e.Attempts {
		parts = append(parts, fmt.Sprintf("%s %s: %v", attempt.Transport, attempt.Endpoint, attempt.Err))
	}
	message := fmt.Sprintf("no LDAP transport succeeded (%s)", strings.Join(parts, "; "))
	if e.Identity.ServerName != "" {
		return fmt.Sprintf("%s; TLS identity %q (%s)", message, e.Identity.ServerName, e.Identity.Source)
	}
	return fmt.Sprintf("%s; no TLS identity was confirmed for the connection address (%s)", message, e.Identity.Detail)
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
	// TLSServerName is the name the certificate must be valid for. When it is
	// empty the connection address is verified instead, which is only correct for
	// certificates that carry a matching IP SAN.
	TLSServerName string
	// RootCAs overrides the trust store used for verification; nil means the
	// system trust store.
	RootCAs *x509.CertPool
	// CertificateTrust is consulted when, and only when, the presented chain is
	// signed by an authority the trust store does not know. The rest of the
	// certificate - host name, validity window, server-auth usage - must already
	// hold, so this can approve an unknown authority but never a bad certificate.
	CertificateTrust TrustHandler
	// Ports overrides the TCP port per transport. A domain controller normally
	// serves 389 and 636, which is what an empty entry means; the override exists
	// for deployments that publish LDAP elsewhere and for tests that must not bind
	// a privileged port.
	Ports map[Transport]string
}

// TrustDecision is the operator's answer about an untrusted certificate.
type TrustDecision int

const (
	// TrustReject refuses the certificate; the connection must not proceed.
	TrustReject TrustDecision = iota
	// TrustSession accepts the certificate for this run only.
	TrustSession
	// TrustPersist accepts it and remembers it for this target.
	TrustPersist
)

// CertificateInfo describes a presented certificate for a trust decision. It
// never contains credentials.
type CertificateInfo struct {
	Target      string
	Identity    string
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	Reason      string
}

// TrustHandler asks the operator about an untrusted issuing authority.
type TrustHandler func(CertificateInfo) (TrustDecision, error)

// Binder performs one NTLM bind over one transport. It is an interface so the
// transport policy can be exercised without a domain controller.
type Binder interface {
	Bind(ctx context.Context, cfg config.Config, transport Transport, options Options) error
}

// Connector applies the transport policy.
type Connector struct {
	Binder   Binder
	Options  Options
	Resolver Resolver
}

// Connect binds with the configured credentials, following the fallback policy.
// It stops as soon as a transport succeeds, and it never retries credentials the
// server refused.
func (c Connector) Connect(ctx context.Context, cfg config.Config) (Session, error) {
	binder := c.Binder
	if binder == nil {
		binder = SystemBinder{}
	}
	identity := Identity{ServerName: c.Options.TLSServerName, Source: SourceTarget, Detail: "supplied by the caller"}
	if identity.ServerName == "" {
		identity = ResolveIdentity(ctx, cfg.Target, cfg.Domain, c.Resolver)
	}
	options := c.Options
	options.TLSServerName = identity.ServerName
	attempts := make([]Attempt, 0, 3)
	attempt := func(transport Transport) bool {
		endpoint := net.JoinHostPort(cfg.Target, transport.PortFor(options))
		err := binder.Bind(ctx, cfg, transport, options)
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
		return sessionFor(attempts, identity, options), nil
	}
	switch last().Kind {
	case KindAuthentication, KindTLS, KindProtocol:
		// Wrong credentials; a trust problem another transport would hit too; or a
		// server that refuses the bind mechanism entirely. Retrying would either
		// repeat invalid credentials or change nothing.
		return Session{}, &Error{Attempts: attempts, Kind: last().Kind, Identity: identity}
	}

	// 2. LDAPS: a TLS channel satisfies integrity checking, so the same
	// credentials bind where the plain connection was refused.
	if attempt(LDAPS) {
		return sessionFor(attempts, identity, options), nil
	}
	switch last().Kind {
	case KindAuthentication, KindTLS, KindProtocol, KindSigning:
		return Session{}, &Error{Attempts: attempts, Kind: last().Kind, Identity: identity}
	}

	// 3. StartTLS on 389, only because LDAPS could not be reached at all.
	if attempt(StartTLS) {
		return sessionFor(attempts, identity, options), nil
	}
	return Session{}, &Error{Attempts: attempts, Kind: last().Kind, Identity: identity}
}

func sessionFor(attempts []Attempt, identity Identity, options Options) Session {
	successful := attempts[len(attempts)-1]
	return Session{Transport: successful.Transport, Endpoint: successful.Endpoint, Insecure: options.InsecureSkipVerify, Identity: identity}
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

// ldapBinder is the part of the LDAP client this package uses, so the bind
// sequence can be exercised without a server.
type ldapBinder interface {
	NTLMBind(domain, username, password string) error
	Bind(username, password string) error
}

// Bind connects using the requested transport and performs the bind.
func (b SystemBinder) Bind(ctx context.Context, cfg config.Config, transport Transport, options Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := b.timeout()
	verification := newTLSVerification(cfg, options)
	address := net.JoinHostPort(cfg.Target, transport.PortFor(options))

	var (
		client *ldap.Conn
		err    error
	)
	switch transport {
	case LDAPS:
		client, err = dialLDAPS(ctx, address, timeout, verification.config, options)
	default:
		client, err = ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	}
	if err != nil {
		return wrapTLSFailure(err, verification.serverName, cfg.Target)
	}
	defer client.Close()
	client.SetTimeout(timeout)
	if transport == StartTLS {
		if err := client.StartTLS(verification.config); err != nil {
			return wrapTLSFailure(err, verification.serverName, cfg.Target)
		}
	}
	if transport == LDAP {
		// Plain LDAP is not integrity protected, so the password never leaves the
		// process except through NTLM, which does not put it on the wire. A simple
		// bind here would transmit it in the clear and would be refused by any
		// controller that requires signing anyway.
		return client.NTLMBind(cfg.Domain, cfg.Username, cfg.Password)
	}
	return bindOverTLS(client, cfg)
}

// dialLDAPS opens the TLS connection itself and hands the secured connection to
// the LDAP client.
//
// The dial is done here rather than through go-ldap's LDAPS dial path because
// the certificate trust decision is asked from inside the TLS handshake. go-ldap
// passes the dialer's timeout to the handshake as a context deadline, and Go
// closes the connection when that deadline expires, so an operator who is still
// reading the certificate would have the connection torn down underneath them
// and never reach the bind they just approved.
func dialLDAPS(ctx context.Context, address string, dialTimeout time.Duration, config *tls.Config, options Options) (*ldap.Conn, error) {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout(dialTimeout, options))
	defer cancel()
	secured := tls.Client(raw, config)
	if err := secured.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	client := ldap.NewConn(secured, true)
	client.Start()
	return client, nil
}

// handshakeTimeout bounds how long the TLS handshake may take. The dial timeout
// is enough when nothing but the network is involved, but a certificate trust
// decision is answered by a person inside that handshake, so it has to leave room
// for reading the certificate and typing an answer. The bound stays finite so an
// unresponsive server still cannot hold startup open indefinitely.
func handshakeTimeout(dialTimeout time.Duration, options Options) time.Duration {
	if options.CertificateTrust != nil {
		return 5 * time.Minute
	}
	return dialTimeout
}

// bindOverTLS completes the bind on a TLS-protected connection.
//
// NTLM is tried first because it never transmits the password. When a controller
// refuses that mechanism, the same credentials are offered with a simple bind in
// the identity formats Active Directory accepts, which is the sequence proven
// against the assessment environment. The exchange stays bounded: one NTLM
// attempt plus one simple bind per format, on the connection that already exists.
func bindOverTLS(binder ldapBinder, cfg config.Config) error {
	ntlmErr := binder.NTLMBind(cfg.Domain, cfg.Username, cfg.Password)
	if ntlmErr == nil {
		return nil
	}
	formats := simpleBindFormats(cfg.Username, cfg.Domain)
	if len(formats) == 0 {
		return fmt.Errorf("NTLM bind failed and no simple bind identity could be derived: %w", ntlmErr)
	}
	lastErr := ntlmErr
	for _, format := range formats {
		if err := binder.Bind(format, cfg.Password); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("NTLM bind failed (%v); simple bind failed for %d identity format(s), the last being %q: %w", ntlmErr, len(formats), maskBindIdentity(formats[len(formats)-1]), lastErr)
}

// simpleBindFormats mirrors the identity formats a working Active Directory
// client offers, in the order that succeeds most often: the bare user name, the
// UPN, then the down-level DOMAIN\user form. An identity that already states a
// format is used as given.
func simpleBindFormats(username, domain string) []string {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	if strings.ContainsAny(username, `@\`) {
		return []string{username}
	}
	formats := []string{username}
	domain = strings.TrimSpace(domain)
	if domain != "" {
		formats = append(formats, username+"@"+domain)
		if label := downLevelDomain(domain); label != "" {
			formats = append(formats, label+`\`+username)
		}
	}
	unique := make([]string, 0, len(formats))
	seen := map[string]bool{}
	for _, format := range formats {
		if !seen[format] {
			seen[format] = true
			unique = append(unique, format)
		}
	}
	return unique
}

// downLevelDomain turns a DNS domain into its NetBIOS-style label.
func downLevelDomain(domain string) string {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		return ""
	}
	label := domain
	if index := strings.Index(domain, "."); index > 0 {
		label = domain[:index]
	}
	return strings.ToUpper(label)
}

// maskBindIdentity shortens an identity for a diagnostic; identities are not
// credentials, but only the shape is needed to report which format failed.
func maskBindIdentity(identity string) string {
	if index := strings.IndexAny(identity, `@\`); index > 0 {
		return identity[:1] + "***" + identity[index:]
	}
	if len(identity) <= 2 {
		return "***"
	}
	return identity[:1] + "***"
}

// tlsVerification is the certificate check applied to a TLS-protected LDAP
// connection: the name the certificate must be valid for, and the configuration
// that performs chain, host name, expiry, and server-auth usage checks.
type tlsVerification struct {
	serverName string
	config     *tls.Config
}

// newTLSVerification resolves the identity under verification and the
// configuration that enforces it. When no DNS name was confirmed the connection
// address is verified instead, which only succeeds for a certificate carrying a
// matching IP SAN.
func newTLSVerification(cfg config.Config, options Options) tlsVerification {
	serverName := options.TLSServerName
	if serverName == "" {
		serverName = cfg.Target
	}
	verification := tlsVerification{
		serverName: serverName,
		config:     &tls.Config{ServerName: serverName, RootCAs: options.RootCAs}, // #nosec G402 -- see below
	}
	switch {
	case options.InsecureSkipVerify:
		// The explicit operator opt-in: no certificate checks at all.
		verification.config.InsecureSkipVerify = true
	case options.CertificateTrust != nil:
		// Verification is not weakened, it is delegated: the callback below runs
		// the same chain, host name, validity and usage checks, and additionally
		// lets the operator decide about an unknown issuing authority.
		verification.config.InsecureSkipVerify = true
		verification.config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPresentedCertificate(rawCerts, serverName, cfg, options)
		}
	}
	return verification
}

// verifyPresentedCertificate performs the certificate checks PwnFlow relies on
// and consults the trust handler only for an unknown issuing authority.
func verifyPresentedCertificate(rawCerts [][]byte, serverName string, cfg config.Config, options Options) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("the server presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("the presented certificate could not be parsed: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if chainCert, parseErr := x509.ParseCertificate(raw); parseErr == nil {
			intermediates.AddCert(chainCert)
		}
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		Roots:         options.RootCAs,
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if verifyErr == nil {
		return nil
	}
	// Only an untrusted authority is a decision the operator may make. A wrong
	// name, an expired certificate, or a certificate that is unusable for server
	// authentication stays fatal, so a decision can never paper over them.
	if !isUnknownAuthority(verifyErr) {
		return verifyErr
	}
	if err := verifyApartFromChainTrust(leaf, serverName); err != nil {
		return err
	}
	if options.CertificateTrust == nil {
		// Never fail silently here: an untrusted certificate with no decision
		// available is a wiring problem the operator must be able to see.
		return fmt.Errorf("%w; no certificate trust decision is available for this connection", verifyErr)
	}
	decision, err := options.CertificateTrust(certificateInfo(rawCerts[0], leaf, cfg, serverName, verifyErr))
	if err != nil {
		return err
	}
	if decision == TrustReject {
		return fmt.Errorf("the untrusted certificate for %s was rejected", serverName)
	}
	return nil
}

// verifyApartFromChainTrust checks everything except which authority signed the
// certificate: validity window, host name, and server-auth suitability.
func verifyApartFromChainTrust(leaf *x509.Certificate, serverName string) error {
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("the certificate is not valid for %q: %w", serverName, err)
	}
	// A certificate that states no extended key usage is unrestricted, which is
	// how the standard chain check reads it. An explicit list that leaves out
	// server authentication is a different matter and stays fatal.
	if len(leaf.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
				break
			}
		}
		if !serverAuth {
			return fmt.Errorf("the certificate is not valid for server authentication")
		}
	}
	return nil
}

func isUnknownAuthority(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthority)
}

// certificateInfo builds the operator-facing description of a presented
// certificate. It carries no credentials.
func certificateInfo(der []byte, leaf *x509.Certificate, cfg config.Config, serverName string, reason error) CertificateInfo {
	digest := sha256.Sum256(der)
	parts := make([]string, 0, len(digest))
	for _, value := range digest {
		parts = append(parts, strings.ToUpper(hex.EncodeToString([]byte{value})))
	}
	return CertificateInfo{
		Target:      cfg.Target,
		Identity:    serverName,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Fingerprint: strings.Join(parts, ":"),
		Reason:      reason.Error(),
	}
}

// wrapTLSFailure adds an operator-facing explanation to a TLS failure while
// preserving the original error, so classification and errors.As keep working.
// Credentials never appear here: only the address and the name under verification.
func wrapTLSFailure(err error, serverName, target string) error {
	if err == nil || Classify(err) != KindTLS {
		return err
	}
	return fmt.Errorf("%s: %w", ExplainTLSFailure(err, serverName, target), err)
}

// ExplainTLSFailure names the certificate problem in operator terms.
func ExplainTLSFailure(err error, serverName, target string) string {
	var hostnameError x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError
	message := strings.ToLower(err.Error())

	switch {
	case strings.Contains(message, "doesn't contain any ip sans") || strings.Contains(message, "does not contain any ip sans"):
		return fmt.Sprintf("the certificate has no IP SAN for %s, and no DNS name for that address could be confirmed", target)
	case errors.As(err, &hostnameError):
		return fmt.Sprintf("the certificate is not valid for %q, the name under verification", serverName)
	case errors.As(err, &invalidCertificate):
		if invalidCertificate.Reason == x509.Expired {
			return fmt.Sprintf("the certificate is expired or not yet valid (checked against %q)", serverName)
		}
		return fmt.Sprintf("the certificate is invalid for %q: %v", serverName, invalidCertificate.Reason)
	case errors.As(err, &unknownAuthority):
		return "the certificate is issued by an authority that is not in the trust store"
	case errors.As(err, &recordHeader), strings.Contains(message, "tls handshake failed"):
		return fmt.Sprintf("the TLS handshake with %s failed", target)
	}
	return fmt.Sprintf("TLS verification failed for %q", serverName)
}

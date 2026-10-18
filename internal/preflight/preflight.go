// Package preflight proves that PwnFlow can authenticate to the supplied domain
// controller before the TUI starts.
//
// The bind is delegated to internal/ldaptransport, which negotiates the
// connection security: plain LDAP first, then LDAPS when the server requires
// signing/integrity, and StartTLS only when LDAPS cannot be reached. A signing
// requirement is therefore no longer a startup blocker, and wrong credentials are
// still wrong credentials.
package preflight

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
)

type FailureKind string

const (
	FailureAuthentication FailureKind = "authentication"
	FailureTLS            FailureKind = "tls"
	FailureSigning        FailureKind = "signing"
	FailureConnectivity   FailureKind = "connectivity"
	FailureProtocol       FailureKind = "protocol"
)

type DiagnosticCategory string

const (
	CategoryTargetUnreachable      DiagnosticCategory = "target_unreachable"
	CategoryConnectionRefused      DiagnosticCategory = "connection_refused"
	CategoryConnectionTimeout      DiagnosticCategory = "connection_timeout"
	CategoryLDAPServiceUnavailable DiagnosticCategory = "ldap_service_unavailable"
	CategoryAuthenticationRejected DiagnosticCategory = "authentication_rejected"
	CategoryAccountNotFound        DiagnosticCategory = "account_not_found"
	CategoryAccountDisabled        DiagnosticCategory = "account_disabled"
	CategoryAccountLocked          DiagnosticCategory = "account_locked"
	CategoryAccountExpired         DiagnosticCategory = "account_expired"
	CategoryPasswordExpired        DiagnosticCategory = "password_expired"
	CategoryLogonRestricted        DiagnosticCategory = "logon_restricted"
	CategoryLDAPIntegrityRequired  DiagnosticCategory = "ldap_integrity_required"
	CategoryTLSHandshakeFailed     DiagnosticCategory = "tls_handshake_failed"
	CategoryTLSIdentityFailed      DiagnosticCategory = "tls_identity_failed"
	CategoryTLSTrustFailed         DiagnosticCategory = "tls_trust_failed"
	CategoryPermissionDenied       DiagnosticCategory = "permission_denied"
	CategoryCancelled              DiagnosticCategory = "cancelled"
	CategoryUnknown                DiagnosticCategory = "unknown"
)

type Failure struct {
	Kind           FailureKind
	Category       DiagnosticCategory
	Target         string
	Domain         string
	TLSHint        bool
	Detail         string
	Attempts       []ldaptransport.Attempt
	AttemptDetails []string
	Err            error
}

func (e *Failure) Error() string {
	var output strings.Builder
	output.WriteString("PwnFlow — LDAP preflight failed\n\n")
	if e.Target != "" {
		fmt.Fprintf(&output, "Target:       %s\n", e.Target)
	}
	if e.Domain != "" {
		fmt.Fprintf(&output, "Domain:       %s\n", e.Domain)
	}
	category := e.Category
	if category == "" {
		category = categoryForKind(e.Kind)
	}
	fmt.Fprintf(&output, "Category:     %s (%s; transport_kind=%s)\n", categoryLabel(category), category, e.Kind)

	explanation, recommendation := explanationFor(category)
	output.WriteString("\nExplanation:\n")
	output.WriteString(explanation)
	output.WriteString("\n\nRecommended action:\n")
	output.WriteString(recommendation)
	if e.TLSHint {
		output.WriteString("\nIf the certificate cannot be validated, use --insecure-skip-verify only with explicit operator approval.")
	}
	if len(e.Attempts) > 0 {
		output.WriteString("\n\nObserved transport attempts:\n")
		for index, attempt := range e.Attempts {
			detail := formatAttempt(attempt.Err)
			if index < len(e.AttemptDetails) {
				detail = e.AttemptDetails[index]
			}
			fmt.Fprintf(&output, "- %s %s: %s\n", attempt.Transport, attempt.Endpoint, detail)
		}
	} else if e.Err != nil {
		detail := e.Detail
		if detail == "" {
			detail = sanitizeDiagnostic(e.Err.Error(), "")
		}
		fmt.Fprintf(&output, "\n\nDetail: %s\n", detail)
	}
	output.WriteString("\nEnumeration was not started.")
	return output.String()
}
func (e *Failure) Unwrap() error { return e.Err }

// Result reports the connection security that carried the bind.
type Result struct {
	Transport ldaptransport.Transport
	Endpoint  string
	Insecure  bool
	Identity  ldaptransport.Identity
}

func BindIdentity(username, domain string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}

// Run performs the NTLM bind with the operator's credentials and reports how the
// connection was protected. The options carry the operator's verification
// choices, including the certificate trust decision for an unknown authority.
func Run(ctx context.Context, cfg config.Config, options ldaptransport.Options) (Result, error) {
	if _, err := exec.LookPath("nxc"); err != nil {
		return Result{}, fmt.Errorf("required dependency nxc is unavailable; run ./install.sh")
	}
	if !options.InsecureSkipVerify {
		options.InsecureSkipVerify = cfg.InsecureSkipVerify
	}
	connector := ldaptransport.Connector{Binder: ldaptransport.SystemBinder{}, Options: options}
	session, err := connector.Connect(ctx, cfg)
	if err != nil {
		return Result{}, classifyBindFailureWithContext(err, options.InsecureSkipVerify, cfg.Target, cfg.Domain, cfg.Password)
	}
	return Result{Transport: session.Transport, Endpoint: session.Endpoint, Insecure: session.Insecure, Identity: session.Identity}, nil
}

// classifyBindFailure keeps the transport failure kinds distinct so a signing
// requirement is never reported as bad credentials, and adds the actionable hint
// when the only remaining problem is certificate trust.
func classifyBindFailure(err error, insecureSkipVerify bool) error {
	return classifyBindFailureWithContext(err, insecureSkipVerify, "", "", "")
}

func classifyBindFailureWithContext(err error, insecureSkipVerify bool, target, domain, secret string) error {
	var transportError *ldaptransport.Error
	if !errors.As(err, &transportError) {
		return &Failure{Kind: FailureAuthentication, Category: CategoryUnknown, Target: target, Domain: domain, Detail: sanitizeDiagnostic(err.Error(), secret), Err: err}
	}
	best := bestAttempt(transportError.Attempts)
	kind := failureKindForAttempt(best)
	category := diagnosticCategory(best, err)
	if category == CategoryUnknown {
		category = categoryForKind(kind)
	}
	attemptDetails := make([]string, len(transportError.Attempts))
	for index, attempt := range transportError.Attempts {
		attemptDetails[index] = sanitizeDiagnostic(formatAttempt(attempt.Err), secret)
	}
	return &Failure{Kind: kind, Category: category, Target: target, Domain: domain, TLSHint: kind == FailureTLS && !insecureSkipVerify, Attempts: transportError.Attempts, AttemptDetails: attemptDetails, Err: err}
}

func bestAttempt(attempts []ldaptransport.Attempt) ldaptransport.Attempt {
	if len(attempts) == 0 {
		return ldaptransport.Attempt{}
	}
	best := attempts[0]
	for _, attempt := range attempts[1:] {
		if diagnosticPriority(attempt) > diagnosticPriority(best) {
			best = attempt
		}
	}
	return best
}

func diagnosticPriority(attempt ldaptransport.Attempt) int {
	switch diagnosticCategory(attempt, nil) {
	case CategoryAuthenticationRejected, CategoryLDAPIntegrityRequired, CategoryPermissionDenied:
		return 5
	case CategoryTLSIdentityFailed, CategoryTLSTrustFailed, CategoryTLSHandshakeFailed:
		return 4
	case CategoryConnectionRefused, CategoryConnectionTimeout, CategoryTargetUnreachable, CategoryLDAPServiceUnavailable:
		return 2
	default:
		return 1
	}
}

func failureKindForAttempt(attempt ldaptransport.Attempt) FailureKind {
	switch attempt.Kind {
	case ldaptransport.KindSigning:
		return FailureSigning
	case ldaptransport.KindTLS:
		return FailureTLS
	case ldaptransport.KindConnectivity:
		return FailureConnectivity
	case ldaptransport.KindProtocol:
		return FailureProtocol
	default:
		return FailureAuthentication
	}
}

func diagnosticCategory(attempt ldaptransport.Attempt, fallback error) DiagnosticCategory {
	if attempt.Err == nil {
		if fallback != nil {
			return categoryFromError(fallback)
		}
		return CategoryUnknown
	}
	return categoryFromError(attempt.Err)
}

func categoryFromError(err error) DiagnosticCategory {
	if err == nil {
		return CategoryUnknown
	}
	if errors.Is(err, context.Canceled) {
		return CategoryCancelled
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return authenticationCategory(ldapErr.Error())
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return CategoryLDAPIntegrityRequired
		case ldap.LDAPResultUnavailable:
			return CategoryLDAPServiceUnavailable
		case ldap.LDAPResultInsufficientAccessRights:
			return CategoryPermissionDenied
		}
	}
	var hostnameError x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var verificationError *tls.CertificateVerificationError
	if errors.As(err, &hostnameError) {
		return CategoryTLSIdentityFailed
	}
	if errors.As(err, &unknownAuthority) || errors.As(err, &verificationError) {
		return CategoryTLSTrustFailed
	}
	if strings.Contains(strings.ToLower(err.Error()), "tls") || strings.Contains(strings.ToLower(err.Error()), "certificate") {
		return CategoryTLSHandshakeFailed
	}
	var dnsError *net.DNSError
	var operationError *net.OpError
	if errors.As(err, &dnsError) {
		return CategoryTargetUnreachable
	}
	if errors.As(err, &operationError) {
		text := strings.ToLower(err.Error())
		if strings.Contains(text, "connection refused") {
			return CategoryConnectionRefused
		}
		if strings.Contains(text, "timeout") || strings.Contains(text, "deadline exceeded") {
			return CategoryConnectionTimeout
		}
		return CategoryTargetUnreachable
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "52e"), strings.Contains(text, "invalid credentials"), strings.Contains(text, "invalidcredential"):
		return authenticationCategory(text)
	case strings.Contains(text, "strongerauthrequired"), strings.Contains(text, "stronger auth"), strings.Contains(text, "integrity"):
		return CategoryLDAPIntegrityRequired
	case strings.Contains(text, "connection refused"):
		return CategoryConnectionRefused
	case strings.Contains(text, "timeout"), strings.Contains(text, "deadline exceeded"):
		return CategoryConnectionTimeout
	case strings.Contains(text, "unavailable"):
		return CategoryLDAPServiceUnavailable
	}
	return CategoryUnknown
}

func authenticationCategory(text string) DiagnosticCategory {
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "data 525"):
		return CategoryAccountNotFound
	case strings.Contains(text, "data 530"), strings.Contains(text, "data 531"):
		return CategoryLogonRestricted
	case strings.Contains(text, "data 532"), strings.Contains(text, "data 773"):
		return CategoryPasswordExpired
	case strings.Contains(text, "data 533"):
		return CategoryAccountDisabled
	case strings.Contains(text, "data 701"):
		return CategoryAccountExpired
	case strings.Contains(text, "data 775"):
		return CategoryAccountLocked
	default:
		return CategoryAuthenticationRejected
	}
}

func categoryForKind(kind FailureKind) DiagnosticCategory {
	switch kind {
	case FailureSigning:
		return CategoryLDAPIntegrityRequired
	case FailureTLS:
		return CategoryTLSHandshakeFailed
	case FailureConnectivity:
		return CategoryTargetUnreachable
	case FailureAuthentication:
		return CategoryAuthenticationRejected
	default:
		return CategoryUnknown
	}
}

func categoryLabel(category DiagnosticCategory) string {
	labels := map[DiagnosticCategory]string{
		CategoryTargetUnreachable:      "Target unreachable",
		CategoryConnectionRefused:      "Connection refused",
		CategoryConnectionTimeout:      "Connection timed out",
		CategoryLDAPServiceUnavailable: "LDAP service unavailable",
		CategoryAuthenticationRejected: "Authentication rejected",
		CategoryAccountNotFound:        "Account not found",
		CategoryAccountDisabled:        "Account disabled",
		CategoryAccountLocked:          "Account locked",
		CategoryAccountExpired:         "Account expired",
		CategoryPasswordExpired:        "Password expired or reset required",
		CategoryLogonRestricted:        "Logon restricted",
		CategoryLDAPIntegrityRequired:  "LDAP signing/integrity required",
		CategoryTLSHandshakeFailed:     "TLS handshake failed",
		CategoryTLSIdentityFailed:      "TLS identity validation failed",
		CategoryTLSTrustFailed:         "TLS certificate trust failed",
		CategoryPermissionDenied:       "Permission denied",
		CategoryCancelled:              "Cancelled",
		CategoryUnknown:                "Inconclusive",
	}
	if label := labels[category]; label != "" {
		return label
	}
	return "Inconclusive"
}

func explanationFor(category DiagnosticCategory) (string, string) {
	switch category {
	case CategoryAuthenticationRejected:
		return "The LDAP server rejected the authentication attempt. This does not establish whether the domain controller has completed startup, and does not by itself prove that the password is incorrect.", "Confirm the domain controller is ready. If the rejection persists, verify the username, domain and credentials."
	case CategoryAccountNotFound, CategoryAccountDisabled, CategoryAccountLocked, CategoryAccountExpired, CategoryPasswordExpired, CategoryLogonRestricted:
		return "The LDAP server rejected the authentication attempt and supplied an account-state diagnostic. PwnFlow reports that server-provided condition; it does not infer a different cause.", "Verify the account state in the directory and confirm the domain controller is ready before retrying."
	case CategoryLDAPIntegrityRequired:
		return "The server rejected the current LDAP security level and requires signing or integrity protection. This is not an invalid-credentials result.", "Use a supported secure LDAP transport or authentication mechanism permitted by the target environment."
	case CategoryConnectionTimeout:
		return "The connection attempt timed out before LDAP authentication completed.", "Verify reachability and domain-controller service readiness, then retry."
	case CategoryConnectionRefused:
		return "The TCP connection was explicitly refused; LDAP may not be listening or may still be starting.", "Verify that the domain controller and LDAP service are ready, then retry."
	case CategoryTargetUnreachable:
		return "No usable network connection to the configured domain controller was established.", "Verify DNS, routing and domain-controller reachability, then retry."
	case CategoryLDAPServiceUnavailable:
		return "The LDAP service returned an unavailable response.", "The domain controller may still be starting. Confirm readiness and retry."
	case CategoryTLSIdentityFailed, CategoryTLSTrustFailed, CategoryTLSHandshakeFailed:
		return "TLS negotiation or certificate validation did not complete successfully. Certificate verification remains enforced.", "Verify the certificate identity, trust chain and supported TLS configuration."
	case CategoryCancelled:
		return "The LDAP preflight was cancelled before authentication completed.", "Retry when the operator is ready."
	default:
		return "PwnFlow could not establish a more specific LDAP failure category from the available evidence.", "Confirm domain-controller readiness and credentials, then retry."
	}
}

var sensitiveDiagnosticPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|credential)\s*[:=]\s*[^\s,;]+`)

func sanitizeDiagnostic(text, secret string) string {
	if secret != "" {
		text = strings.ReplaceAll(text, secret, "[REDACTED]")
	}
	text = sensitiveDiagnosticPattern.ReplaceAllString(text, "$1=[REDACTED]")
	return strings.Join(strings.Fields(text), " ")
}

func formatAttempt(err error) string {
	if err == nil {
		return "succeeded"
	}
	return sanitizeDiagnostic(err.Error(), "")
}

// ClassifyBindError reports the kind of a preflight failure.
func ClassifyBindError(err error) FailureKind {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return FailureAuthentication
}

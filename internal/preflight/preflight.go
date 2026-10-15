package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
)

type FailureKind string

const (
	FailureAuthentication FailureKind = "authentication"
	FailureTLS            FailureKind = "tls"
	FailureSigning        FailureKind = "signing"
	FailureConnectivity   FailureKind = "connectivity"
)

type Failure struct {
	Kind FailureKind
	Err  error
}

func (e *Failure) Error() string { return fmt.Sprintf("LDAP %s failure: %v", e.Kind, e.Err) }
func (e *Failure) Unwrap() error { return e.Err }

func BindIdentity(username, domain string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}

func Run(ctx context.Context, cfg config.Config) error {
	if _, err := exec.LookPath("nxc"); err != nil {
		return fmt.Errorf("required dependency nxc is unavailable; run scripts/install.sh")
	}
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(cfg.Target, "389"))
	if err != nil {
		return &Failure{Kind: FailureConnectivity, Err: fmt.Errorf("target resolution failed: %w", err)}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return &Failure{Kind: FailureConnectivity, Err: fmt.Errorf("LDAP connection failed: %w", err)}
	}
	_ = conn.Close()

	client, err := ldap.DialURL("ldap://"+addr.String(), ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return &Failure{Kind: FailureConnectivity, Err: fmt.Errorf("LDAP connection failed: %w", err)}
	}
	defer client.Close()
	if err := client.NTLMBind(cfg.Domain, cfg.Username, cfg.Password); err != nil {
		return classifyBindFailure(err)
	}
	return nil
}

func classifyBindFailure(err error) error {
	kind := FailureAuthentication
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			kind = FailureSigning
		case ldap.LDAPResultAuthMethodNotSupported, ldap.LDAPResultInappropriateAuthentication:
			kind = FailureTLS
		}
	}
	return &Failure{Kind: kind, Err: err}
}

func ClassifyBindError(err error) FailureKind {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return FailureAuthentication
}

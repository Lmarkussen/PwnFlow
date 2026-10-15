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
	"errors"
	"fmt"
	"os/exec"
	"strings"

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

type Failure struct {
	Kind FailureKind
	Err  error
}

func (e *Failure) Error() string { return fmt.Sprintf("LDAP %s failure: %v", e.Kind, e.Err) }
func (e *Failure) Unwrap() error { return e.Err }

// Result reports the connection security that carried the bind.
type Result struct {
	Transport ldaptransport.Transport
	Endpoint  string
	Insecure  bool
}

func BindIdentity(username, domain string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}

// Run performs the NTLM bind with the operator's credentials and reports how the
// connection was protected.
func Run(ctx context.Context, cfg config.Config) (Result, error) {
	if _, err := exec.LookPath("nxc"); err != nil {
		return Result{}, fmt.Errorf("required dependency nxc is unavailable; run ./install.sh")
	}
	connector := ldaptransport.Connector{
		Binder:  ldaptransport.SystemBinder{},
		Options: ldaptransport.Options{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	session, err := connector.Connect(ctx, cfg)
	if err != nil {
		return Result{}, classifyBindFailure(err, cfg.InsecureSkipVerify)
	}
	return Result{Transport: session.Transport, Endpoint: session.Endpoint, Insecure: session.Insecure}, nil
}

// classifyBindFailure keeps the transport failure kinds distinct so a signing
// requirement is never reported as bad credentials, and adds the actionable hint
// when the only remaining problem is certificate trust.
func classifyBindFailure(err error, insecureSkipVerify bool) error {
	var transportError *ldaptransport.Error
	if !errors.As(err, &transportError) {
		return &Failure{Kind: FailureAuthentication, Err: err}
	}
	kind := FailureAuthentication
	switch transportError.Kind {
	case ldaptransport.KindSigning:
		kind = FailureSigning
	case ldaptransport.KindTLS:
		kind = FailureTLS
	case ldaptransport.KindConnectivity:
		kind = FailureConnectivity
	case ldaptransport.KindProtocol:
		kind = FailureProtocol
	}
	if kind == FailureTLS && !insecureSkipVerify {
		err = fmt.Errorf("%w; if this host's certificate cannot be validated, re-run with --insecure-skip-verify", err)
	}
	return &Failure{Kind: kind, Err: err}
}

// ClassifyBindError reports the kind of a preflight failure.
func ClassifyBindError(err error) FailureKind {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return FailureAuthentication
}

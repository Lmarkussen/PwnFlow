package preflight

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestBindIdentityUsesUPN(t *testing.T) {
	if got := BindIdentity("svc-audit", "corp.example"); got != "svc-audit@corp.example" {
		t.Fatalf("got %q", got)
	}
	if got := BindIdentity("user@corp.example", "corp.example"); got != "user@corp.example" {
		t.Fatalf("qualified identity changed to %q", got)
	}
}

func TestClassifyBindErrors(t *testing.T) {
	auth := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("data 52e")}
	if got := ClassifyBindError(classifyBindFailure(auth)); got != FailureAuthentication {
		t.Fatalf("auth classified as %q", got)
	}
	signing := &ldap.Error{ResultCode: ldap.LDAPResultStrongAuthRequired, Err: errors.New("signing required")}
	if got := ClassifyBindError(classifyBindFailure(signing)); got != FailureSigning {
		t.Fatalf("signing classified as %q", got)
	}
}

func TestClassifyTLSAndSigningErrors(t *testing.T) {
	tlsError := &ldap.Error{ResultCode: ldap.LDAPResultAuthMethodNotSupported, Err: errors.New("TLS required")}
	if got := ClassifyBindError(classifyBindFailure(tlsError)); got != FailureTLS {
		t.Fatalf("TLS classified as %q", got)
	}
	confidentiality := &ldap.Error{ResultCode: ldap.LDAPResultConfidentialityRequired, Err: errors.New("confidentiality required")}
	if got := ClassifyBindError(classifyBindFailure(confidentiality)); got != FailureSigning {
		t.Fatalf("confidentiality classified as %q", got)
	}
}

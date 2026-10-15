package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/ldaptransport"
)

func certificateInfo() ldaptransport.CertificateInfo {
	return ldaptransport.CertificateInfo{
		Target:      "198.51.100.10",
		Identity:    "dc01.corp.example",
		Subject:     "CN=domain controller",
		Issuer:      "CN=Lab Issuing CA",
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		Fingerprint: "AA:BB:CC:DD",
		Reason:      "x509: certificate signed by unknown authority",
	}
}

func newTestDecider(t *testing.T, input string) (*Decider, *strings.Builder, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pwnflow", "trusted-certificates.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	output := &strings.Builder{}
	return &Decider{Store: store, In: strings.NewReader(input), Out: output, Interactive: func() bool { return true }}, output, path
}

// A remembered approval for the same target and identity is used without asking.
func TestStoredApprovalIsUsedWithoutPrompting(t *testing.T) {
	decider, output, path := newTestDecider(t, "")
	info := certificateInfo()
	if err := decider.Store.Approve(Record{Target: info.Target, Identity: info.Identity, Fingerprint: info.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	decider.Store = store

	decision, err := decider.Decide(info)
	if err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("stored approval was not honoured: %v %v", decision, err)
	}
	if strings.Contains(output.String(), "Choice") {
		t.Fatalf("the operator was prompted although an approval was stored: %q", output.String())
	}
}

// A certificate that changed since the approval must be decided again.
func TestChangedCertificateRequiresANewDecision(t *testing.T) {
	decider, output, _ := newTestDecider(t, "")
	info := certificateInfo()
	if err := decider.Store.Approve(Record{Target: info.Target, Identity: info.Identity, Fingerprint: "DIFFERENT"}); err != nil {
		t.Fatal(err)
	}
	decision, err := decider.Decide(info)
	if err == nil || decision != ldaptransport.TrustReject {
		t.Fatalf("a changed certificate was accepted: %v %v", decision, err)
	}
	if !strings.Contains(output.String(), "differs from the stored approval") {
		t.Fatalf("the change was not explained: %q", output.String())
	}
	if !strings.Contains(output.String(), "Choice") {
		t.Fatalf("a new decision was not requested: %q", output.String())
	}
}

// An approval is scoped to its target and identity.
func TestApprovalIsScopedToTargetAndIdentity(t *testing.T) {
	decider, _, _ := newTestDecider(t, "")
	info := certificateInfo()
	if err := decider.Store.Approve(Record{Target: "203.0.113.9", Identity: info.Identity, Fingerprint: info.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if _, ok := decider.Store.Lookup(info.Target, info.Identity); ok {
		t.Fatal("an approval leaked across targets")
	}
	if _, ok := decider.Store.Lookup("203.0.113.9", "other.example"); ok {
		t.Fatal("an approval leaked across identities")
	}
}

// Session-only acceptance is remembered for the rest of the run.
func TestSessionAcceptanceDoesNotPromptTwice(t *testing.T) {
	decider, output, _ := newTestDecider(t, "s\n")
	info := certificateInfo()
	decision, err := decider.Decide(info)
	if err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("session decision failed: %v %v", decision, err)
	}
	prompts := strings.Count(output.String(), "Choice")
	decision, err = decider.Decide(info)
	if err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("second decision failed: %v %v", decision, err)
	}
	if strings.Count(output.String(), "Choice") != prompts {
		t.Fatal("the operator was prompted twice for the same certificate")
	}
	if !strings.Contains(output.String(), "already accepted for this session") {
		t.Fatalf("the session acceptance was not reported: %q", output.String())
	}
}

// Persisting writes non-secret metadata with owner-only permissions.
func TestPersistWritesOwnerOnlyMetadata(t *testing.T) {
	decider, output, path := newTestDecider(t, "t\n")
	info := certificateInfo()
	decision, err := decider.Decide(info)
	if err != nil || decision != ldaptransport.TrustPersist {
		t.Fatalf("persist decision failed: %v %v", decision, err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, want := range []string{info.Target, info.Identity, info.Fingerprint, "Lab Issuing CA"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stored metadata is missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"password", "Password", "secret"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("stored metadata looks like it holds a credential: %s", text)
		}
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("trust store permissions are %v, want 0600", fileInfo.Mode().Perm())
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("trust store directory permissions are %v, want 0700", directory.Mode().Perm())
	}
	if !strings.Contains(output.String(), "stored in") {
		t.Fatalf("the stored decision was not reported: %q", output.String())
	}
}

// Nothing but an explicit affirmative answer is acceptance.
func TestMissingOrNegativeInputIsRejection(t *testing.T) {
	for name, input := range map[string]string{
		"empty line": "\n",
		"no input":   "",
		"reject":     "r\n",
		"nonsense":   "maybe\n",
	} {
		decider, output, path := newTestDecider(t, input)
		decision, _ := decider.Decide(certificateInfo())
		if decision != ldaptransport.TrustReject {
			t.Fatalf("%s was treated as acceptance: %v", name, decision)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s stored an approval", name)
		}
		if strings.Contains(output.String(), "password") {
			t.Fatalf("%s leaked a credential", name)
		}
	}
}

// A non-interactive run cannot decide, so it must not connect.
func TestNonInteractiveInputCannotAccept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	decider := &Decider{Store: store, In: strings.NewReader("s\n"), Out: &strings.Builder{}}
	decision, err := decider.Decide(certificateInfo())
	if decision != ldaptransport.TrustReject || err == nil {
		t.Fatalf("a non-interactive run accepted a certificate: %v %v", decision, err)
	}
	if !strings.Contains(err.Error(), "no interactive terminal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// An approval store is a convenience, not a precondition for deciding: a run
// whose store could not be loaded must still be able to accept a certificate for
// that run, instead of failing with a trust error and no prompt.
func TestWithoutAStoreTheDecisionIsSessionOnly(t *testing.T) {
	output := &strings.Builder{}
	decider := &Decider{In: strings.NewReader("t\n"), Out: output, Interactive: func() bool { return true }}
	info := certificateInfo()
	decision, err := decider.Decide(info)
	if err != nil {
		t.Fatalf("the operator's approval was refused: %v", err)
	}
	if decision != ldaptransport.TrustSession {
		t.Fatalf("unexpected decision without a store: %v", decision)
	}
	prompts := strings.Count(output.String(), "Choice")
	if prompts != 1 {
		t.Fatalf("expected the certificate to be shown once, got %d:\n%s", prompts, output.String())
	}
	// The same certificate must not be asked about again in this run.
	if decision, err := decider.Decide(info); err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("second decision failed: %v %v", decision, err)
	}
	if strings.Count(output.String(), "Choice") != prompts {
		t.Fatal("the operator was prompted twice for the same certificate")
	}
}

// A store that cannot be written still only affects persistence, not safety.
func TestUnwritableStoreDoesNotFailTheDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly", "trusted.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o500); err != nil {
		t.Fatal(err)
	}
	output := &strings.Builder{}
	decider := &Decider{Store: store, In: strings.NewReader("t\n"), Out: output, Interactive: func() bool { return true }}
	decision, err := decider.Decide(certificateInfo())
	if err != nil || decision != ldaptransport.TrustPersist {
		t.Fatalf("unexpected decision: %v %v", decision, err)
	}
	if !strings.Contains(output.String(), "could not be stored") {
		t.Fatalf("the storage failure was not reported: %q", output.String())
	}
}

// The prompt shows what the operator needs and nothing secret.
func TestPromptShowsCertificateDetails(t *testing.T) {
	decider, output, _ := newTestDecider(t, "r\n")
	info := certificateInfo()
	if _, err := decider.Decide(info); err == nil {
		t.Fatal("rejection should be reported")
	}
	shown := output.String()
	for _, want := range []string{info.Identity, info.Target, info.Subject, info.Issuer, info.Fingerprint, info.Reason, info.NotAfter.UTC().Format(time.RFC3339)} {
		if !strings.Contains(shown, want) {
			t.Fatalf("prompt is missing %q: %q", want, shown)
		}
	}
}

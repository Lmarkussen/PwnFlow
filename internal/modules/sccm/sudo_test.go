package sccm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// renewalRecorder is an operator decision that counts how often a renewal was
// asked for, so a test can tell "the cache was reused" from "the operator was
// asked again".
type renewalRecorder struct {
	alreadyApproved bool
	renew           bool
	asked           int32
}

func (p *renewalRecorder) ElevationApproved(string) bool { return p.alreadyApproved }

func (p *renewalRecorder) RenewElevation(context.Context, string, string) bool {
	atomic.AddInt32(&p.asked, 1)
	return p.renew
}

func (p *renewalRecorder) renewals() int { return int(atomic.LoadInt32(&p.asked)) }

// withPXEThiefEndpoints prepares a managed PXEThief with the given endpoints
// stored for the assessment.
func withPXEThiefEndpoints(t *testing.T, endpoints ...modules.Endpoint) *modules.Runtime {
	t.Helper()
	withRawSocketPrivileges(t, false)
	toolLayout(t, "PXEThief", "pxethief.py", `case "$1" in
2) echo "[+] mode 2 against $2"; exit 0 ;;
esac
echo "[+] mode 1"; exit 0`)
	if err := os.WriteFile(filepath.Join(os.Getenv("PWNFLOW_TOOLS_DIR"), "PXEThief", pxeThiefMarker), []byte(prTestHead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyCacheTTL = 0
	return testRuntime(t, &fakeStore{records: endpoints})
}

// A valid sudo cache is reused: the operator approved once, and the batch does not
// ask again for every invocation.
func TestValidSudoCacheIsReusedWithoutRenewal(t *testing.T) {
	sudoCache(t, true)
	runtime := withPXEThiefEndpoints(t,
		modules.Endpoint{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
		modules.Endpoint{Address: "198.51.100.42", Hostname: "pxe02.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	)
	policy := &renewalRecorder{alreadyApproved: true}
	runtime.Elevation = policy
	sudoRecord := sudoMock(t, "")

	if err := (PXEThief{}).Run(context.Background(), runtime, discardSink{}); err != nil {
		t.Fatalf("the approved run failed: %v", err)
	}
	if policy.renewals() != 0 {
		t.Fatalf("a valid cache asked the operator %d time(s) to authenticate again", policy.renewals())
	}
	lines := readLines(t, sudoRecord)
	if len(lines) != 2 {
		t.Fatalf("expected one elevated invocation per endpoint, got %v", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "sudo -n /") {
			t.Fatalf("an invocation did not use the validated noninteractive form: %q", line)
		}
	}
}

// An expired cache is renewed at the boundary before the privileged invocation,
// and the invocation starts only after the cache is valid again.
func TestExpiredSudoCacheRenewsBeforeTheInvocation(t *testing.T) {
	state := sudoCache(t, false)
	runtime := withPXEThiefEndpoints(t,
		modules.Endpoint{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	)
	policy := &renewalRecorder{alreadyApproved: true}
	// The renewal stands in for the terminal handoff: sudo reports a valid cache
	// afterwards, which is what the module verifies.
	previousCheck := sudoCheckFunc
	policy.renew = true
	sudoCheckFunc = func(ctx context.Context, program string, args ...string) error {
		if *state {
			return nil
		}
		if policy.renewals() > 0 {
			*state = true
			previousCheck(ctx, program, args...)
			return nil
		}
		return previousCheck(ctx, program, args...)
	}
	t.Cleanup(func() { sudoCheckFunc = previousCheck })
	runtime.Elevation = policy
	sudoRecord := sudoMock(t, "")

	if err := (PXEThief{}).Run(context.Background(), runtime, discardSink{}); err != nil {
		t.Fatalf("the renewed run failed: %v", err)
	}
	if policy.renewals() != 1 {
		t.Fatalf("an expired cache asked for %d renewals, want exactly one", policy.renewals())
	}
	if lines := readLines(t, sudoRecord); len(lines) != 1 {
		t.Fatalf("the privileged invocation did not run after the renewal: %v", lines)
	}
}

// A renewal the operator declines skips the privileged work. PwnFlow does not
// retry it unprivileged, and it says which requirement was not met.
func TestDeclinedRenewalSkipsThePrivilegedRun(t *testing.T) {
	sudoCache(t, false)
	runtime := withPXEThiefEndpoints(t,
		modules.Endpoint{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	)
	policy := &renewalRecorder{alreadyApproved: true, renew: false}
	runtime.Elevation = policy
	sudoRecord := sudoMock(t, "")

	err := (PXEThief{}).Run(context.Background(), runtime, discardSink{})
	if err == nil {
		t.Fatal("the run continued without a valid authorization")
	}
	if !strings.Contains(err.Error(), "not renewed") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
	if !strings.Contains(err.Error(), "skipped") || strings.Contains(err.Error(), "unprivileged") && !strings.Contains(err.Error(), "does not retry it unprivileged") {
		t.Fatalf("the refusal suggests an unprivileged fallback: %v", err)
	}
	if policy.renewals() != 1 {
		t.Fatalf("the operator was asked %d time(s), want one", policy.renewals())
	}
	if lines := readLines(t, sudoRecord); len(lines) != 0 {
		t.Fatalf("a privileged invocation ran after the renewal was declined: %v", lines)
	}
}

// A renewal that succeeds on the terminal but still leaves sudo without a valid
// authorization is reported as such, and nothing privileged runs.
func TestRenewalThatDoesNotAuthoriseSudoSkipsTheRun(t *testing.T) {
	sudoCache(t, false)
	runtime := withPXEThiefEndpoints(t,
		modules.Endpoint{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	)
	policy := &renewalRecorder{alreadyApproved: true, renew: true}
	runtime.Elevation = policy
	sudoRecord := sudoMock(t, "")

	err := (PXEThief{}).Run(context.Background(), runtime, discardSink{})
	if err == nil || !strings.Contains(err.Error(), "no valid authorization") {
		t.Fatalf("an unverifiable renewal was not reported: %v", err)
	}
	if lines := readLines(t, sudoRecord); len(lines) != 0 {
		t.Fatalf("a privileged invocation ran without a verified cache: %v", lines)
	}
}

// The operator's approval is still required before any of this: an unapproved
// batch never reaches the cache check.
func TestApprovalIsRequiredBeforeTheCacheIsUsed(t *testing.T) {
	sudoCache(t, true)
	runtime := withPXEThiefEndpoints(t,
		modules.Endpoint{Address: "198.51.100.41", Hostname: "pxe01.corp.example", Role: rolePXEDistributionPoint, Domain: testDomain},
	)
	policy := &renewalRecorder{alreadyApproved: false, renew: false}
	runtime.Elevation = policy

	err := (PXEThief{}).Run(context.Background(), runtime, discardSink{})
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("an unapproved run was allowed: %v", err)
	}
	if policy.renewals() != 0 {
		t.Fatal("an unapproved run asked for a renewal instead of being refused")
	}
}

// readLines reads a mock sudo's record, so a test can see exactly what was run.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

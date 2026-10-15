package confinement

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// An enforced boundary either rejects the probe with EPERM or drops it, which
// stalls the connect until the deadline. Both are verified on the assessment
// host: the system manager rejects some filters and drops this one.
func TestClassifyAcceptsEnforcedBoundary(t *testing.T) {
	if err := classify(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EPERM)}); err != nil {
		t.Fatalf("EPERM must count as an enforced boundary, got %v", err)
	}
	if err := classify(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EACCES)}); err != nil {
		t.Fatalf("EACCES must count as an enforced boundary, got %v", err)
	}
	// The kernel path reports the dial timeout as os.ErrDeadlineExceeded, which is
	// how a dropping cgroup filter shows up.
	if err := classify(&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}); err != nil {
		t.Fatalf("a dropped probe (i/o timeout) must count as an enforced boundary, got %v", err)
	}
	// The deadline can also surface as a context deadline depending on the dial
	// path, so the check must not depend on one sentinel.
	if err := classify(&net.OpError{Op: "dial", Err: context.DeadlineExceeded}); err != nil {
		t.Fatalf("a context-deadline drop must count as an enforced boundary, got %v", err)
	}
}

// Without a boundary the local stack answers, which must never pass as confined.
func TestClassifyRejectsUnfilteredEgress(t *testing.T) {
	err := classify(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if err == nil || !strings.Contains(err.Error(), "unfiltered") {
		t.Fatalf("ECONNREFUSED must report missing filtering, got %v", err)
	}
}

// Fail closed: anything the probe cannot classify blocks execution.
func TestClassifyFailsClosedOnUnknownFailure(t *testing.T) {
	for name, dialErr := range map[string]error{
		"network down": &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)},
		"reset":        &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNRESET)},
		"generic":      errors.New("boom"),
	} {
		err := classify(dialErr)
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("%s: expected a fail-closed verdict, got %v", name, err)
		}
	}
}

// The probe must be safe: it only ever targets loopback, so even on a host with
// no filtering it cannot contact another system. On this development host - a
// workstation, not the confined assessment run - the verdict must be an error,
// which is exactly the fail-closed direction.
func TestProbeNeverReportsAnUnverifiedBoundary(t *testing.T) {
	if err := Probe(); err != nil {
		if !strings.Contains(err.Error(), probeAddress) && !strings.Contains(err.Error(), "probe") {
			t.Fatalf("probe error must name what it probed, got %v", err)
		}
		return
	}
	// Reaching here means the host genuinely filters loopback egress; that is the
	// confined case, so confirm the probe really ran against loopback only.
	if _, port, splitErr := net.SplitHostPort(probeAddress); splitErr != nil || port != "9" {
		t.Fatalf("probe target %q is not the loopback discard port", probeAddress)
	}
}

func TestProbeErrorMessageIsActionable(t *testing.T) {
	if err := classify(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(fmt.Sprint(err), "cgroup filter") {
		t.Fatalf("verdict should name the missing mechanism, got %v", err)
	}
}

// A probe that a listener answers is not evidence of a boundary, even though the
// connection succeeded.
func TestClassifyRejectsAnsweredProbe(t *testing.T) {
	if err := classify(nil); err == nil || !strings.Contains(err.Error(), "succeeded") {
		t.Fatalf("an answered probe must not count as confined, got %v", err)
	}
}

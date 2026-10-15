// Package confinement verifies that this process may only reach the authorized
// Active Directory destination.
//
// The boundary is kernel-enforced and process-specific: a cgroup BPF program
// (systemd IPAddressAllow/IPAddressDeny) attached to the cgroup PwnFlow runs in.
// Loading such a program requires privilege, so PwnFlow does not create the
// filter itself; it verifies one is in place before it starts a collector that
// could otherwise reach an unauthorized host, and it refuses to run without it.
package confinement

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// probeAddress is a loopback address nothing listens on. Loopback traffic never
// leaves the host, so probing it can never contact another system, while the
// outcome still separates an enforced filter from no filter at all: an
// unfiltered stack answers immediately with ECONNREFUSED, whereas a cgroup
// IPAddressDeny=any denies loopback too and either stalls the connect (the
// packet is dropped) or fails it with EPERM (the packet is rejected).
const probeAddress = "127.0.0.1:9"

// probeTimeout bounds the stall a dropping filter produces. The interval is only
// paid when a filter is actually dropping packets; an unfiltered loopback
// connect is answered in microseconds.
const probeTimeout = time.Second

// Probe reports whether egress filtering is enforced for this process. It returns
// nil only for a positively verified boundary; every other outcome - including a
// failure it cannot classify - is an error, so callers fail closed.
func Probe() error {
	connection, err := net.DialTimeout("tcp", probeAddress, probeTimeout)
	if connection != nil {
		connection.Close()
	}
	return classify(err)
}

// classify turns the probe's dial error into a verdict about the boundary. A
// cgroup filter expresses itself in one of two ways - it drops the packet, which
// stalls the connect until the deadline, or it rejects it with EPERM - and both
// count as enforced. Timeouts are detected through net.Error rather than a single
// sentinel because the dial deadline surfaces as different wrapped errors
// depending on the path. Anything that means the local stack itself answered, or
// that cannot be classified, is not evidence of a boundary.
func classify(err error) error {
	if err == nil {
		return fmt.Errorf("probe connection to %s succeeded, so no egress filter is enforced", probeAddress)
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return nil
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("egress is unfiltered: the probe connection to %s was refused by the local stack instead of being blocked by a cgroup filter", probeAddress)
	}
	return fmt.Errorf("egress filter state is unknown: the probe connection to %s failed with %v", probeAddress, err)
}

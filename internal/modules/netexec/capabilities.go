package netexec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// capabilityTTL bounds how often the executable is interrogated. The probe runs
// off the render path, so this only decides how quickly an operator who upgrades
// NetExec while PwnFlow is running sees the new answer.
var capabilityTTL = 10 * time.Minute

// probeTimeout bounds a single capability probe, so a hung executable cannot
// hold the refresh goroutine open indefinitely.
var probeTimeout = 20 * time.Second

// protocolCapability is what the installed executable said about one protocol.
//
// helpOK records whether `nxc <protocol> --help` produced usable output: a
// protocol missing from the installed build answers that question with a
// failure, which is exactly the case that has to be reported as unsupported
// rather than silently listed.
type protocolCapability struct {
	help      []byte
	modules   []byte
	helpOK    bool
	modulesOK bool
	probed    bool
	at        time.Time
}

type capabilitySet struct {
	mu        sync.RWMutex
	protocols map[modules.Protocol]protocolCapability
}

var capabilitySnapshot = &capabilitySet{protocols: make(map[modules.Protocol]protocolCapability)}

// Capabilities returns the process-wide capability snapshot.
func Capabilities() *capabilitySet { return capabilitySnapshot }

// ResetCapabilities drops the snapshot. Tests use it after they install a
// stand-in executable; the running application never needs it.
func ResetCapabilities() {
	capabilitySnapshot.mu.Lock()
	defer capabilitySnapshot.mu.Unlock()
	capabilitySnapshot.protocols = make(map[modules.Protocol]protocolCapability)
}

// lookup returns the snapshot for one protocol, probing it when the snapshot is
// missing or older than the TTL. Callers that must not block - the render path -
// use cached instead.
func (c *capabilitySet) lookup(ctx context.Context, protocol modules.Protocol) (protocolCapability, bool) {
	c.mu.RLock()
	capability, ok := c.protocols[protocol]
	c.mu.RUnlock()
	if ok && capability.probed && time.Since(capability.at) < capabilityTTL {
		return capability, true
	}
	return c.probe(ctx, protocol)
}

// cached returns the snapshot without any I/O. The second result is false when
// nothing has been probed yet, in which case a caller must not report the module
// as unavailable: "not known yet" is not "unsupported".
func (c *capabilitySet) cached(protocol modules.Protocol) (protocolCapability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	capability, ok := c.protocols[protocol]
	if !ok || !capability.probed {
		return protocolCapability{}, false
	}
	return capability, true
}

// Probed reports whether the snapshot for a protocol has been filled. It exists
// so a test or a diagnostic can prove that the render path never interrogated the
// executable, rather than inferring it.
func (c *capabilitySet) Probed(protocol modules.Protocol) bool {
	_, ok := c.cached(protocol)
	return ok
}

func (c *capabilitySet) probe(ctx context.Context, protocol modules.Protocol) (protocolCapability, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	command := protocolCommand(protocol)
	capability := protocolCapability{probed: true, at: time.Now()}
	help, helpErr := exec.CommandContext(probeCtx, "nxc", command, "--help").CombinedOutput()
	if len(help) > 0 {
		capability.help = help
		capability.helpOK = helpErr == nil
	}
	// `-L` fails on a NetExec workspace database whose schema is older than the
	// installed build. That is a local database problem, not a missing module,
	// so the listing is only trusted when it succeeded.
	listing, listingErr := exec.CommandContext(probeCtx, "nxc", command, "-L").CombinedOutput()
	if listingErr == nil && len(listing) > 0 {
		capability.modules = listing
		capability.modulesOK = true
	}
	c.mu.Lock()
	c.protocols[protocol] = capability
	c.mu.Unlock()
	return capability, true
}

// reason explains why the installed executable cannot run a registration, or
// returns an empty string when it can - including when the answer is not known
// yet, because execution re-checks against a live probe before anything runs.
func (c *capabilitySet) reason(protocol modules.Protocol, moduleName string, arguments []string) string {
	capability, ok := c.cached(protocol)
	if !ok {
		return ""
	}
	if !capability.helpOK {
		return fmt.Sprintf("NetExec %s protocol is not supported by the installed version", protocol)
	}
	for _, flag := range spec(protocol).requiredHelpFlags {
		if !bytes.Contains(capability.help, []byte(flag)) {
			return fmt.Sprintf("NetExec %s option %s is not supported by the installed version", protocol, flag)
		}
	}
	if moduleName != "" && capability.modulesOK && !capability.advertisesModule(moduleName) {
		return fmt.Sprintf("NetExec %s module %s is not advertised by the installed version (nxc %s -L)", protocol, moduleName, protocolCommand(protocol))
	}
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "--") && !bytes.Contains(capability.help, []byte(argument)) {
			return fmt.Sprintf("NetExec %s option %s is not supported by the installed version", protocol, argument)
		}
	}
	return ""
}

// advertisesModule reports whether `nxc <protocol> -L` lists the module as
// usable. NetExec keeps retired modules in the listing and marks them
// "[REMOVED]", so the marker is treated as not advertised: those modules are
// present in the menu but cannot run.
func (c protocolCapability) advertisesModule(name string) bool {
	marker := []byte("[*] " + name)
	for _, line := range bytes.Split(c.modules, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if !bytes.HasPrefix(trimmed, marker) {
			continue
		}
		rest := trimmed[len(marker):]
		if len(rest) > 0 && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\r' {
			// A longer module name that merely starts with this one.
			continue
		}
		return !bytes.Contains(trimmed, []byte("[REMOVED]"))
	}
	return false
}

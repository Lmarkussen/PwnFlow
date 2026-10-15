package ldaptransport

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// IdentitySource records how the TLS identity was determined.
type IdentitySource string

const (
	// SourceTarget: the operator supplied a DNS name, so it is used as given.
	SourceTarget IdentitySource = "target host name"
	// SourceReverseDNS: the address resolved back to a confirmed host name.
	SourceReverseDNS IdentitySource = "reverse DNS confirmed by forward lookup"
	// SourceAddressOnly: no usable name was found; verify against the address.
	SourceAddressOnly IdentitySource = "address only"
)

// Identity is the name TLS verification expects for the connection, together
// with how it was obtained. An empty ServerName means the connection address
// itself is verified, which is only correct when the certificate carries a
// matching IP SAN.
type Identity struct {
	ServerName string
	Source     IdentitySource
	Detail     string
}

// Resolver is the name service the identity check uses. It is an interface so
// discovery can be exercised without touching a network.
type Resolver interface {
	LookupAddr(ctx context.Context, address string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SystemResolver performs bounded lookups with the host resolver.
type SystemResolver struct {
	Timeout time.Duration
}

// timeout bounds each lookup so discovery can never stall startup.
func (r SystemResolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 3 * time.Second
}

// LookupAddr resolves an address to candidate host names.
func (r SystemResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return net.DefaultResolver.LookupAddr(bounded, address)
}

// LookupHost resolves a host name to its addresses.
func (r SystemResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return net.DefaultResolver.LookupHost(bounded, host)
}

// ResolveIdentity decides which name TLS verification should expect.
//
// A host name target is used as-is. For an address, discovery stays narrow: only
// the reverse record of that exact address is considered, the candidate must sit
// inside the supplied AD domain, and it must resolve forward back to the same
// address. A domain controller's certificate normally carries the DC's DNS name
// rather than an IP SAN, so this is what makes IP targets verifiable - but an
// unconfirmed reverse record is never treated as proof of identity, and no domain
// or service record is consulted that could point at a different controller.
func ResolveIdentity(ctx context.Context, target, domain string, resolver Resolver) Identity {
	target = strings.TrimSpace(target)
	if target == "" {
		return Identity{Source: SourceAddressOnly, Detail: "no target address was supplied"}
	}
	if net.ParseIP(target) == nil {
		return Identity{ServerName: normalizeHostName(target), Source: SourceTarget, Detail: "the target is already a DNS name"}
	}
	if resolver == nil {
		resolver = SystemResolver{}
	}
	names, err := resolver.LookupAddr(ctx, target)
	if err != nil {
		return Identity{Source: SourceAddressOnly, Detail: fmt.Sprintf("reverse lookup for %s failed: %v", target, err)}
	}
	candidates := normalizeCandidates(names)
	if len(candidates) == 0 {
		return Identity{Source: SourceAddressOnly, Detail: fmt.Sprintf("no usable host name was returned for %s", target)}
	}
	rejected := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if !consistentWithDomain(candidate, domain) {
			rejected = append(rejected, fmt.Sprintf("%s (outside %s)", candidate, domain))
			continue
		}
		addresses, lookupErr := resolver.LookupHost(ctx, candidate)
		if lookupErr != nil {
			rejected = append(rejected, fmt.Sprintf("%s (forward lookup failed)", candidate))
			continue
		}
		if !containsAddress(addresses, target) {
			rejected = append(rejected, fmt.Sprintf("%s (does not resolve back to %s)", candidate, target))
			continue
		}
		return Identity{
			ServerName: candidate,
			Source:     SourceReverseDNS,
			Detail:     fmt.Sprintf("%s is the reverse name of %s and resolves back to it", candidate, target),
		}
	}
	return Identity{
		Source: SourceAddressOnly,
		Detail: fmt.Sprintf("no reverse name for %s is both inside %s and confirmed by a forward lookup: %s", target, domain, strings.Join(rejected, ", ")),
	}
}

// normalizeCandidates cleans, validates, and orders reverse-lookup results so a
// choice never depends on resolver ordering.
func normalizeCandidates(names []string) []string {
	seen := make(map[string]bool, len(names))
	candidates := make([]string, 0, len(names))
	for _, name := range names {
		normalized := normalizeHostName(name)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		candidates = append(candidates, normalized)
	}
	sort.Strings(candidates)
	return candidates
}

// normalizeHostName lower-cases a name, drops the root label, and rejects
// anything that is not a usable DNS host name.
func normalizeHostName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for index, character := range label {
			alphanumeric := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
			if alphanumeric {
				continue
			}
			if character == '-' && index != 0 && index != len(label)-1 {
				continue
			}
			return ""
		}
	}
	return name
}

// consistentWithDomain requires the candidate to be the domain itself or a host
// inside it.
func consistentWithDomain(candidate, domain string) bool {
	domain = normalizeHostName(domain)
	if domain == "" || candidate == "" {
		return false
	}
	return candidate == domain || strings.HasSuffix(candidate, "."+domain)
}

func containsAddress(addresses []string, target string) bool {
	wanted := net.ParseIP(target)
	if wanted == nil {
		return false
	}
	for _, address := range addresses {
		if parsed := net.ParseIP(strings.TrimSpace(address)); parsed != nil && parsed.Equal(wanted) {
			return true
		}
	}
	return false
}

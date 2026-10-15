package ldaptransport

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeResolver answers from a fixed table and records every query, so tests can
// prove discovery never touches a network and never asks for more than it needs.
type fakeResolver struct {
	reverse    map[string][]string
	forward    map[string][]string
	reverseErr error
	forwardErr error
	queries    []string
}

func (f *fakeResolver) LookupAddr(_ context.Context, address string) ([]string, error) {
	f.queries = append(f.queries, "addr:"+address)
	if f.reverseErr != nil {
		return nil, f.reverseErr
	}
	return f.reverse[address], nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.queries = append(f.queries, "host:"+host)
	if f.forwardErr != nil {
		return nil, f.forwardErr
	}
	return f.forward[host], nil
}

// A host name target needs no discovery at all.
func TestResolveIdentityKeepsHostNameTargetsAsSupplied(t *testing.T) {
	resolver := &fakeResolver{}
	identity := ResolveIdentity(context.Background(), "DC01.Corp.Example.", "corp.example", resolver)
	if identity.ServerName != "dc01.corp.example" || identity.Source != SourceTarget {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if len(resolver.queries) != 0 {
		t.Fatalf("discovery ran for a host name target: %v", resolver.queries)
	}
}

// An address target is matched to its confirmed reverse name.
func TestResolveIdentityConfirmsReverseNameForAddressTarget(t *testing.T) {
	resolver := &fakeResolver{
		reverse: map[string][]string{"127.0.0.1": {"dc01.corp.example."}},
		forward: map[string][]string{"dc01.corp.example": {"127.0.0.1"}},
	}
	identity := ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", resolver)
	if identity.ServerName != "dc01.corp.example" || identity.Source != SourceReverseDNS {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if len(resolver.queries) != 2 {
		t.Fatalf("discovery was not minimal: %v", resolver.queries)
	}
}

// Candidates are normalized, ordered, and filtered: only a name inside the
// supplied domain that resolves back to the address may be chosen.
func TestResolveIdentityPicksTheConsistentConfirmedCandidate(t *testing.T) {
	resolver := &fakeResolver{
		reverse: map[string][]string{"127.0.0.1": {"z.corp.example", "a.corp.example", "b.other.example", "unconfirmed.corp.example"}},
		forward: map[string][]string{
			"a.corp.example":           {"127.0.0.1"},
			"z.corp.example":           {"127.0.0.1"},
			"unconfirmed.corp.example": {"203.0.113.9"},
		},
	}
	identity := ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", resolver)
	if identity.ServerName != "a.corp.example" {
		t.Fatalf("chosen identity is not the deterministic consistent candidate: %#v", identity)
	}
}

// A reverse name outside the supplied domain is never trusted.
func TestResolveIdentityRejectsWrongDomainCandidate(t *testing.T) {
	resolver := &fakeResolver{
		reverse: map[string][]string{"127.0.0.1": {"dc01.other.example"}},
		forward: map[string][]string{"dc01.other.example": {"127.0.0.1"}},
	}
	identity := ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", resolver)
	if identity.ServerName != "" || identity.Source != SourceAddressOnly {
		t.Fatalf("wrong-domain candidate was accepted: %#v", identity)
	}
	if !strings.Contains(identity.Detail, "outside corp.example") {
		t.Fatalf("rejection reason is not explained: %q", identity.Detail)
	}
	if strings.Contains(strings.Join(resolver.queries, " "), "host:") {
		t.Fatalf("a name outside the domain was confirmed anyway: %v", resolver.queries)
	}
}

// A reverse name that does not resolve back to the address is not proof of
// identity on its own.
func TestResolveIdentityRejectsUnconfirmedReverseName(t *testing.T) {
	resolver := &fakeResolver{
		reverse: map[string][]string{"127.0.0.1": {"dc01.corp.example"}},
		forward: map[string][]string{"dc01.corp.example": {"203.0.113.9"}},
	}
	identity := ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", resolver)
	if identity.ServerName != "" {
		t.Fatalf("unconfirmed reverse name was trusted: %#v", identity)
	}
	if !strings.Contains(identity.Detail, "does not resolve back") {
		t.Fatalf("missing confirmation failure detail: %q", identity.Detail)
	}
}

func TestResolveIdentityReportsLookupProblems(t *testing.T) {
	failing := &fakeResolver{reverseErr: errors.New("temporary failure in name resolution")}
	identity := ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", failing)
	if identity.ServerName != "" || !strings.Contains(identity.Detail, "reverse lookup for 127.0.0.1 failed") {
		t.Fatalf("lookup failure not reported: %#v", identity)
	}

	missing := &fakeResolver{reverse: map[string][]string{"127.0.0.1": {}}}
	identity = ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", missing)
	if identity.ServerName != "" || !strings.Contains(identity.Detail, "no usable host name") {
		t.Fatalf("missing reverse record not reported: %#v", identity)
	}

	unresolvable := &fakeResolver{
		reverse:    map[string][]string{"127.0.0.1": {"dc01.corp.example"}},
		forwardErr: errors.New("no such host"),
	}
	identity = ResolveIdentity(context.Background(), "127.0.0.1", "corp.example", unresolvable)
	if identity.ServerName != "" || !strings.Contains(identity.Detail, "forward lookup failed") {
		t.Fatalf("forward lookup failure not reported: %#v", identity)
	}
}

func TestNormalizeHostNameRejectsUnusableNames(t *testing.T) {
	for _, value := range []string{"", ".", "..", "bad name", "-leading", "trailing-", "a..b", strings.Repeat("a", 64) + ".example"} {
		if got := normalizeHostName(value); got != "" {
			t.Errorf("normalizeHostName(%q) = %q, want rejection", value, got)
		}
	}
	for input, want := range map[string]string{"DC01.Corp.Example.": "dc01.corp.example", " host.example ": "host.example"} {
		if got := normalizeHostName(input); got != want {
			t.Errorf("normalizeHostName(%q) = %q, want %q", input, got, want)
		}
	}
}

package trustinventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestParseEntriesPreservesRawValuesAndNormalizesTrustMetadata(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("CN=z.example.test,CN=System,DC=example,DC=test", map[string][]string{
			"cn": {"z.example.test"}, "name": {"z.example.test"}, "trustPartner": {"z.example.test"}, "flatName": {"Z"},
			"trustDirection": {"3"}, "trustType": {"2"}, "trustAttributes": {"37"}, "securityIdentifier": {"S-1-5-21-synthetic"},
		}),
		ldap.NewEntry("CN=a.example.test,CN=System,DC=example,DC=test", map[string][]string{
			"trustDirection": {"99"}, "trustType": {"99"}, "trustAttributes": {"4096"},
		}),
	}
	parsed := ParseEntries(entries)
	if len(parsed) != 2 || parsed[0].DistinguishedName[:4] != "CN=a" {
		t.Fatalf("entries were not deterministically ordered: %#v", parsed)
	}
	first := parsed[0]
	if first.Direction != "unknown" || first.TypeRaw == nil || *first.TypeRaw != 99 {
		t.Fatalf("unknown type/direction was not preserved: %#v", first)
	}
	if len(first.UnknownAttributeBits) != 1 || first.UnknownAttributeBits[0] != "0x1000" {
		t.Fatalf("unknown trust bit was not preserved: %#v", first.UnknownAttributeBits)
	}
	second := parsed[1]
	if second.Direction != "bidirectional" || second.TrustType != "windows_ad" {
		t.Fatalf("recognized metadata was not normalized: %#v", second)
	}
	if second.SecurityIdentifier != "0x532d312d352d32312d73796e746865746963" {
		t.Fatalf("security identifier was not represented safely: %q", second.SecurityIdentifier)
	}
	if !strings.Contains(strings.Join(second.AttributeFlags, ","), "non_transitive") || !strings.Contains(strings.Join(second.AttributeFlags, ","), "quarantined_domain") {
		t.Fatalf("trust bitmask was not decoded: %#v", second.AttributeFlags)
	}
}

func TestParseEntriesHandlesSignedHighTrustAttributeBit(t *testing.T) {
	entry := ldap.NewEntry("CN=primary.example.test,CN=System,DC=example,DC=test", map[string][]string{
		"trustAttributes": {"-2147483648"},
	})
	parsed := ParseEntries([]*ldap.Entry{entry})
	if len(parsed) != 1 || len(parsed[0].AttributeFlags) != 1 || parsed[0].AttributeFlags[0] != "primary" || len(parsed[0].UnknownAttributeBits) != 0 {
		t.Fatalf("signed high bit was not decoded as a 32-bit trust mask: %#v", parsed)
	}
}

func TestParseEntriesDoesNotExportSecrets(t *testing.T) {
	entry := ldap.NewEntry("CN=secret.example.test,CN=System,DC=example,DC=test", map[string][]string{
		"trustPartner": {"secret.example.test"}, "trustAuthIncoming": {"synthetic-secret"}, "trustAuthOutgoing": {"synthetic-secret"},
	})
	parsed := ParseEntries([]*ldap.Entry{entry})
	if len(parsed) != 1 {
		t.Fatal("expected one trust")
	}
	if strings.Contains(string(mustJSON(parsed[0])), "synthetic-secret") {
		t.Fatal("trust authentication material entered the exported record")
	}
}

func TestModuleIsManualOnlyAndReadOnly(t *testing.T) {
	module := Module{}
	if !module.ReadOnly() || module.ToolFamily() != modules.ToolFamilyActiveDirectory || module.Protocol() != modules.ProtocolLDAP {
		t.Fatalf("unexpected module metadata: %s", module.ID())
	}
	if module.ID() == "" || module.OutputFile() == "" {
		t.Fatal("module metadata is incomplete")
	}
	ctx := context.Background()
	if err := module.Check(ctx, nil); err == nil {
		t.Fatal("nil runtime was accepted")
	}
}

func mustJSON(value Trust) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

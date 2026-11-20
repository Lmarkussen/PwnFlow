package directorysettings

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func sidBytes(t *testing.T, sid string) []byte {
	t.Helper()
	escaped, ok := sidFilterValue(sid)
	if !ok {
		t.Fatalf("bad SID %s", sid)
	}
	var raw []byte
	for _, part := range strings.Split(escaped, `\`)[1:] {
		var b byte
		for _, c := range part {
			b = b<<4 | byte(strings.IndexRune("0123456789abcdef", c))
		}
		raw = append(raw, b)
	}
	return raw
}

func guidBytes(guid string) []byte {
	clean := strings.ReplaceAll(guid, "-", "")
	raw := make([]byte, 16)
	for index := 0; index < 16; index++ {
		var b byte
		for _, c := range clean[index*2 : index*2+2] {
			b = b<<4 | byte(strings.IndexRune("0123456789abcdef", c))
		}
		raw[index] = b
	}
	// The first three fields are little-endian on the wire.
	raw[0], raw[1], raw[2], raw[3] = raw[3], raw[2], raw[1], raw[0]
	raw[4], raw[5] = raw[5], raw[4]
	raw[6], raw[7] = raw[7], raw[6]
	return raw
}

func ace(aceType, flags byte, mask uint32, objectType []byte, sid []byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, mask)
	if aceType == 0x05 || aceType == 0x06 {
		objectFlags := uint32(0)
		if objectType != nil {
			objectFlags = 1
		}
		body = binary.LittleEndian.AppendUint32(body, objectFlags)
		body = append(body, objectType...)
	}
	body = append(body, sid...)
	header := []byte{aceType, flags}
	header = binary.LittleEndian.AppendUint16(header, uint16(4+len(body)))
	return append(header, body...)
}

func descriptor(aces ...[]byte) []byte {
	var aclBody []byte
	for _, entry := range aces {
		aclBody = append(aclBody, entry...)
	}
	acl := []byte{2, 0}
	acl = binary.LittleEndian.AppendUint16(acl, uint16(8+len(aclBody)))
	acl = binary.LittleEndian.AppendUint16(acl, uint16(len(aces)))
	acl = append(acl, 0, 0)
	acl = append(acl, aclBody...)
	header := []byte{1, 0, 0x04, 0x80}
	header = binary.LittleEndian.AppendUint32(header, 0)
	header = binary.LittleEndian.AppendUint32(header, 0)
	header = binary.LittleEndian.AppendUint32(header, 0)
	header = binary.LittleEndian.AppendUint32(header, 20)
	return append(header, acl...)
}

func TestParseDACLKeepsWriteCapableEntries(t *testing.T) {
	authenticated := sidBytes(t, "S-1-5-11")
	helpdesk := sidBytes(t, "S-1-5-21-1-2-3-1201")
	sd := descriptor(
		ace(0x05, 0x00, rightCreateChild, guidBytes(dnsNodeClass), authenticated),
		ace(0x00, 0x10, rightFullControl, nil, sidBytes(t, "S-1-5-21-1-2-3-512")),
		ace(0x00, 0x00, 0x00020094, nil, sidBytes(t, "S-1-1-0")),                                       // read only
		ace(0x05, 0x00, rightCreateChild, guidBytes("bf967a86-0de6-11d0-a285-00aa003049e2"), helpdesk), // computer class
		ace(0x01, 0x00, rightWriteDACL, nil, helpdesk),
	)
	aces, err := parseDACL(sd)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 3 {
		t.Fatalf("want three write-capable ACEs, got %+v", aces)
	}
	if aces[0].SID != "S-1-5-11" || !aces[0].Allow || strings.Join(aces[0].Rights, ",") != "CreateChild" || aces[0].ObjectType != dnsNodeClass {
		t.Fatalf("dnsNode CreateChild not parsed: %+v", aces[0])
	}
	if aces[1].SID != "S-1-5-21-1-2-3-512" || aces[1].Rights[0] != "GenericAll" || !aces[1].Inherited {
		t.Fatalf("full control not parsed: %+v", aces[1])
	}
	if aces[2].Allow || aces[2].Rights[0] != "WriteDacl" {
		t.Fatalf("deny ACE not parsed: %+v", aces[2])
	}
}

func TestParseDACLRejectsTruncatedInput(t *testing.T) {
	sd := descriptor(ace(0x00, 0, rightGenericAll, nil, sidBytes(t, "S-1-5-11")))
	if _, err := parseDACL(sd[:len(sd)-6]); err == nil {
		t.Fatal("truncated descriptor parsed without error")
	}
	if _, err := parseDACL([]byte{1, 2, 3}); err == nil {
		t.Fatal("short descriptor parsed without error")
	}
}

type fakeDirectory struct {
	entries   map[string][]*ldap.Entry // keyed by base DN
	anonymous error
	anonEntry bool
	searched  []string
}

func (f *fakeDirectory) Search(_ context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searched = append(f.searched, request.BaseDN+"|"+request.Filter)
	if request.Filter == "(objectClass=dnsZone)" && len(request.Controls) == 0 {
		return nil, errors.New("zone search without SD flags control")
	}
	if entries, ok := f.entries[request.BaseDN]; ok {
		return &ldap.SearchResult{Entries: entries}, nil
	}
	return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
}

func (f *fakeDirectory) AnonymousSearch(_ context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, string, error) {
	if f.anonymous != nil {
		return nil, "192.0.2.10:389", f.anonymous
	}
	if f.anonEntry && request.Scope == ldap.ScopeBaseObject {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(request.BaseDN, nil)}}, "192.0.2.10:389", nil
	}
	return &ldap.SearchResult{}, "192.0.2.10:389", nil
}

func TestCollectReadsSettingsZonesAndAnonymousProbe(t *testing.T) {
	sd := descriptor(ace(0x05, 0, rightCreateChild, guidBytes(dnsNodeClass), sidBytes(t, "S-1-5-11")))
	zone := ldap.NewEntry("DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example", map[string][]string{"name": {"corp.example"}})
	zone.Attributes = append(zone.Attributes, &ldap.EntryAttribute{Name: "nTSecurityDescriptor", ByteValues: [][]byte{sd}, Values: []string{string(sd)}})
	dir := &fakeDirectory{
		anonEntry: true,
		entries: map[string][]*ldap.Entry{
			"": {ldap.NewEntry("", map[string][]string{"defaultNamingContext": {"DC=corp,DC=example"}, "configurationNamingContext": {"CN=Configuration,DC=corp,DC=example"}, "rootDomainNamingContext": {"DC=corp,DC=example"}})},
			"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=example": {ldap.NewEntry("CN=Directory Service", map[string][]string{"dSHeuristics": {"0000002"}})},
			"DC=DomainDnsZones,DC=corp,DC=example":                                               {zone, ldap.NewEntry("DC=RootDNSServers", map[string][]string{"name": {"RootDNSServers"}})},
			zone.DN:                                                                              {ldap.NewEntry("DC=*,"+zone.DN, map[string][]string{"name": {"*"}})},
		},
	}
	report := Collect(context.Background(), &modules.Runtime{Target: "192.0.2.10", Domain: "corp.example", Username: "auditor"}, dir)
	if report.DSHeuristics.Status != "read" || report.DSHeuristics.Value != "0000002" {
		t.Fatalf("dSHeuristics %+v", report.DSHeuristics)
	}
	if report.AnonymousLDAP.Status != "base_readable" {
		t.Fatalf("anonymous probe %+v", report.AnonymousLDAP)
	}
	if len(report.DNSZones) != 1 || report.DNSZones[0].Name != "corp.example" || !report.DNSZones[0].WildcardRecord || report.DNSZones[0].ACLStatus != "read" {
		t.Fatalf("zones %+v", report.DNSZones)
	}
	if len(report.DNSZones[0].ACEs) != 1 || report.DNSZones[0].ACEs[0].SID != "S-1-5-11" {
		t.Fatalf("zone ACEs %+v", report.DNSZones[0].ACEs)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("missing optional partitions must not be errors: %v", report.Errors)
	}
}

func TestAnonymousProbeRefusalIsRecorded(t *testing.T) {
	dir := &fakeDirectory{anonymous: ldap.NewError(ldap.LDAPResultOperationsError, errors.New("a successful bind must be completed")), entries: map[string][]*ldap.Entry{}}
	report := Collect(context.Background(), &modules.Runtime{Target: "192.0.2.10", Domain: "corp.example", Username: "auditor"}, dir)
	if report.AnonymousLDAP.Status != "refused" {
		t.Fatalf("anonymous probe %+v", report.AnonymousLDAP)
	}
	if report.DSHeuristics.Status != "error" {
		t.Fatalf("unreadable dSHeuristics must be an error, got %+v", report.DSHeuristics)
	}
}

func TestModuleIsReadOnlyActiveDirectoryEnumeration(t *testing.T) {
	var module Module
	if !module.ReadOnly() || module.ToolFamily() != modules.ToolFamilyActiveDirectory || module.Category() != modules.CategoryEnumeration || module.Tool() != ToolName {
		t.Fatalf("unexpected module metadata")
	}
	if !strings.HasSuffix(module.OutputFile(), outputText) {
		t.Fatalf("output %s", module.OutputFile())
	}
}

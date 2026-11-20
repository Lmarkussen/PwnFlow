package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestBloodyADWritableIsCorrelatedWithRustHound(t *testing.T) {
	assessment := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_writable_object_assessment", Title: "AD Writable Object Assessment", SourceTool: "AD Writable Object Assessment",
		EvidenceJSON: `{"authenticated_user":"auditor","relationships":[{"target_dn":"CN=svc-app,OU=Services,DC=corp,DC=example","permission":"GenericWrite"},{"target_dn":"cn=svc-app,ou=services,dc=corp,dc=example","permission":"WriteDacl"}]}`,
	}}
	observed := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "bloodyad_writable_permissions", Title: "Writable directory object permissions", SourceTool: "BloodyAD",
		AffectedObject: "CN=svc-app,OU=Services,DC=corp,DC=example", AffectedObjectID: "cn=svc-app,ou=services,dc=corp,dc=example",
		EvidenceJSON: `{"distinguished_name":"CN=svc-app,OU=Services,DC=corp,DC=example"}`,
	}}
	unseen := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "bloodyad_writable_permissions", Title: "Writable directory object permissions", SourceTool: "BloodyAD",
		AffectedObject: "CN=web01,OU=Servers,DC=corp,DC=example", EvidenceJSON: `{"distinguished_name":"CN=web01,OU=Servers,DC=corp,DC=example"}`,
	}}
	rows := correlateBloodyADWritable([]storage.Finding{assessment, observed, unseen})
	if len(rows) != 3 {
		t.Fatalf("correlation must not add or drop Findings: %d", len(rows))
	}
	first := ansi.Strip(findingAttributes(rows[1], 160))
	if !strings.Contains(first, "also observed by RustHound (GenericWrite, WriteDacl)") {
		t.Fatalf("matching DN not corroborated:\n%s", first)
	}
	second := ansi.Strip(findingAttributes(rows[2], 160))
	if !strings.Contains(second, "not among the RustHound writable-object relationships") {
		t.Fatalf("unmatched DN not marked:\n%s", second)
	}

	// Without RustHound DNs there is nothing to compare, so nothing is claimed.
	plain := correlateBloodyADWritable([]storage.Finding{unseen})
	if strings.Contains(plain[0].EvidenceJSON, "rusthound_corroboration") {
		t.Fatalf("annotated without a RustHound comparison: %s", plain[0].EvidenceJSON)
	}
}

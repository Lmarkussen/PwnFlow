package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestExtractKerberosInlineParsesASREPPrincipal(t *testing.T) {
	lines := []string{"$krb5asrep$23$user@example.test:REDACTED"}
	got := extractKerberosInline(lines, map[string]any{"material_type": "asrep", "principal": "user@example.test", "record_line_numbers": []any{float64(1)}}, storage.Finding{})
	if len(got) != 1 || got[0] != lines[0] {
		t.Fatalf("AS-REP evidence was not matched to its principal: %v", got)
	}
}

func TestKerberosPrincipalMatchingIsDomainAware(t *testing.T) {
	cases := []struct {
		name     string
		want     bool
		expected string
		line     string
	}{
		{name: "unqualified source principal", want: true, expected: "svc", line: "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy"},
		{name: "qualified same domain", want: true, expected: "EXAMPLE.TEST\\svc", line: "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy"},
		{name: "qualified other domain", want: false, expected: "OTHER.TEST\\svc", line: "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy"},
		{name: "similar name", want: false, expected: "svc2", line: "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := kerberosPrincipalMatches(test.expected, kerberosPrincipalInline(test.line)); got != test.want {
				t.Fatalf("match(%q, %q)=%t, want %t", test.expected, kerberosPrincipalInline(test.line), got, test.want)
			}
		})
	}
}

func TestKerberosPrincipalMatchingHandlesDollarQualifiedNetExecTGS(t *testing.T) {
	line := "$krb5tgs$18$hostadenum-gmsa.sccm.lab$SCCM.LAB$*sccm.lab\\adenum-gmsa$*$material"
	observed := kerberosPrincipalInline(line)
	if observed != `sccm.lab\adenum-gmsa` {
		t.Fatalf("unexpected NetExec principal %q", observed)
	}
	if !kerberosPrincipalMatches("ADENUM-GMSA$@SCCM.LAB", observed) {
		t.Fatalf("dollar-qualified principal did not match observed %q", observed)
	}
	if kerberosPrincipalMatches("OTHER-GMSA$@SCCM.LAB", observed) {
		t.Fatal("material crossed to an unrelated principal")
	}
}

func TestLoadKerberosInlineReportsScopedCounts(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "results", "example.test", "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	matching := "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy-material-a"
	other := "$krb5tgs$23$*svc2$EXAMPLE.TEST$MSSQL/foo*$dummy-material-b"
	artifact := filepath.Join(artifactDir, "kerberoast.txt")
	if err := os.WriteFile(artifact, []byte(matching+"\n"+matching+"\n"+other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{
		SourceTool: "NetExec", FindingType: "kerberos_ticket_material_collected", ArtifactPath: "artifacts/kerberoast.txt",
		EvidenceJSON: `{"material_type":"kerberoast","principal":"svc","record_count":2,"record_line_numbers":[1,2]}`,
	}}
	loaded := loadInlineEvidence(config.Config{Root: root, Domain: "example.test"}, finding)
	if loaded.error != "" || len(loaded.lines) != 1 || loaded.lines[0] != matching {
		t.Fatalf("unexpected scoped material count or load error: count=%d error=%q", len(loaded.lines), loaded.error)
	}
	if loaded.sourceRecordCount != 2 || loaded.uniqueMaterialCount != 1 || loaded.duplicateRecordCount != 1 {
		t.Fatalf("unexpected material counts: source=%d unique=%d duplicates=%d", loaded.sourceRecordCount, loaded.uniqueMaterialCount, loaded.duplicateRecordCount)
	}
	if loaded.accountScopedPath == "" {
		t.Fatal("account-scoped evidence report was not created")
	}
	report, err := os.ReadFile(filepath.Join(root, "results", "example.test", loaded.accountScopedPath))
	if err != nil {
		t.Fatal("account-scoped evidence report was not readable")
	}
	info, err := os.Stat(filepath.Join(root, "results", "example.test", loaded.accountScopedPath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("account-scoped evidence report does not have restricted permissions")
	}
	if !strings.Contains(string(report), matching) || strings.Contains(string(report), other) {
		t.Fatal("account-scoped report did not preserve only the matched record")
	}
}

func TestExtractKerberosInlineRejectsAmbiguousUnqualifiedPrincipal(t *testing.T) {
	lines := []string{
		"$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$dummy-a",
		"$krb5tgs$23$*svc$OTHER.TEST$MSSQL/foo*$dummy-b",
	}
	metadata := map[string]any{"principal": "svc", "record_line_numbers": []any{float64(1), float64(2)}}
	if got := extractKerberosInline(lines, metadata, storage.Finding{}); len(got) != 0 {
		t.Fatalf("ambiguous unqualified principal leaked material: %v", got)
	}
}

func TestFindingHasInlineEvidenceDoesNotDuplicateLDAPAttribute(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		SourceTool: "NetExec", FindingType: "ad_user_description_keyword_observed",
	}}
	if findingHasInlineEvidence(finding) {
		t.Fatal("LDAP attribute evidence should use the authoritative detail block")
	}
}

func TestStylePXECredentialLineUsesPrefixAndDescriptorColors(t *testing.T) {
	styled := stylePXECredentialLine("OSDJoinPassword       = synthetic-password")
	if !strings.Contains(styled, "OSDJoin") || !strings.Contains(styled, "Password") || !strings.Contains(styled, "synthetic-password") {
		t.Fatalf("styled credential line lost content: %q", styled)
	}
	if ansi.StringWidthWc(styled) != len("OSDJoinPassword       = synthetic-password") {
		t.Fatalf("ANSI styling changed visible width: %d", ansi.StringWidthWc(styled))
	}
}

func TestStylePXECredentialLineColorsWholeLabelAndValue(t *testing.T) {
	styled := stylePXECredentialLine("OSDLocalAdminPassword = synthetic-secret")
	if !strings.Contains(styled, infoBlueStyle().Render("OSDLocalAdminPassword")) {
		t.Fatal("credential label was not styled as one blue field name")
	}
	if !strings.Contains(styled, warn.Render("synthetic-secret")) {
		t.Fatal("credential value was not styled as one orange value")
	}
}

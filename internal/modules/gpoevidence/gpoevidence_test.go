package gpoevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualOnlyAndBoundedMetadata(t *testing.T) {
	var module Module
	include, reason := module.IncludeInGlobalPlan()
	if include || reason == "" {
		t.Fatalf("module is not manual-only: %v %q", include, reason)
	}
	if module.ID() != "ad-gpo-evidence" || module.OutputFile() != "Enumeration/ActiveDirectory/GPO/collection.log" {
		t.Fatal("unexpected module identity")
	}
	if maxGPOs <= 0 || maxFilesPerGPO <= 0 || maxFileBytes <= 0 || maxTotalBytes <= 0 {
		t.Fatal("missing collection bounds")
	}
}

func TestParseLinksPreservesMalformedEntries(t *testing.T) {
	links := parseLinks("[LDAP://CN={ABC},CN=Policies,DC=example,DC=test;0][LDAP://CN={11111111-2222-3333-4444-555555555555},CN=Policies,DC=example,DC=test;2]")
	if len(links) != 2 {
		t.Fatalf("links=%d", len(links))
	}
	if links[0].Error == "" || links[1].GPOGUID == "" || links[1].Enforced == nil || !*links[1].Enforced {
		t.Fatalf("unexpected links: %#v", links)
	}
}

func TestValidateRelativePath(t *testing.T) {
	for _, value := range []string{"../escape", "/absolute", `C:\\escape`, "Machine/../GPT.INI"} {
		if err := validateRelativePath(value); err == nil {
			t.Errorf("accepted unsafe path %q", value)
		}
	}
	if err := validateRelativePath("Machine/Preferences/Groups/Groups.xml"); err != nil {
		t.Fatal(err)
	}
}

func TestValidatedPolicyRelativePathRejectsRedirectedRoot(t *testing.T) {
	gpo := GPO{GUID: "11111111-2222-3333-4444-555555555555", Attributes: map[string]attributeValue{"gPCFileSysPath": {Status: "present", Values: []string{`\\other\SYSVOL\example.test\Policies\{11111111-2222-3333-4444-555555555555}`}}}}
	if _, err := validatedPolicyRelativePath(gpo, "example.test"); err == nil {
		t.Fatal("accepted redirected SYSVOL path")
	}
	gpo.Attributes["gPCFileSysPath"] = attributeValue{Status: "present", Values: []string{`\\example.test\SYSVOL\example.test\Policies\{11111111-2222-3333-4444-555555555555}`}}
	if _, err := validatedPolicyRelativePath(gpo, "example.test"); err != nil {
		t.Fatal(err)
	}
}

func TestHashAndBoundedCopy(t *testing.T) {
	hash, size := hashBytes([]byte("synthetic"))
	if size != 9 || len(hash) != 64 {
		t.Fatalf("hash=%q size=%d", hash, size)
	}
	var dst bytes.Buffer
	count, err := copyBounded(context.Background(), &dst, strings.NewReader("0123456789"), 4)
	if err != nil || count != 5 || dst.String() != "01234" {
		t.Fatalf("count=%d err=%v body=%q", count, err, dst.String())
	}
}

func TestWriteSummaryIsTraceableAndSecretFree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Enumeration", "ActiveDirectory", "GPO")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: 1, GPOs: []GPOSummary{{GPOGUID: "ABC", Status: "partial", Retrieved: 1, Failed: 1}}, Files: []ManifestFile{{GPOGUID: "ABC", Status: "complete"}, {GPOGUID: "ABC", Status: "failed"}}}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "GPO_evidence_manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSummary(root, "example.test", 42); err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(root, "GPO_EVIDENCE_SUMMARY.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(summary)
	for _, want := range []string{"Producing execution ID: 42", "ABC: partial", "GPO_evidence_manifest.json", "not verified"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(text), "password") {
		t.Fatal("summary exposed secret wording")
	}
}

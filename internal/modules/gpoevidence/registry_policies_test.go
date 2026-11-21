package gpoevidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestCollectRegistryPolicies(t *testing.T) {
	bin := t.TempDir()
	// The fake smbclient serves Registry.pol and reports Registry.xml missing.
	script := `#!/bin/sh
for arg in "$@"; do command="$arg"; done
case "$command" in
  *Registry.pol*) printf 'PReg\001\000\000\000' > Registry.pol; echo "getting file";;
  *) echo "NT_STATUS_OBJECT_PATH_NOT_FOUND opening remote file"; exit 1;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "smbclient"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	guid := "31B2F340-016D-11D2-945F-00C04FB984F9"
	gpo := GPO{GUID: guid, Attributes: map[string]attributeValue{"displayName": {Status: "present", Values: []string{"Default Domain Policy"}}, "flags": {Status: "present", Values: []string{"0"}}}}
	links := LinksDocument{Sources: []LinkSource{{DN: "DC=corp,DC=example", ObjectType: "domain", Links: parseLinks("[LDAP://cn={" + guid + "},cn=policies,cn=system,DC=corp,DC=example;0]")}}}
	root := t.TempDir()
	runtime := &modules.Runtime{Target: "192.0.2.10", Domain: "corp.example", Username: "auditor", Password: "x"}
	result := collectRegistryPolicies(context.Background(), runtime, root, []GPO{gpo}, links)
	if len(result) != 1 {
		t.Fatalf("%+v", result)
	}
	entry := result[0]
	if entry.Name != "Default Domain Policy" || entry.ComputerSettingsDisabled || len(entry.Links) != 1 || !entry.Links[0].Enabled || entry.Links[0].Container != "DC=corp,DC=example" {
		t.Fatalf("entry %+v", entry)
	}
	if pol := entry.Files["registry_pol"]; pol.Status != "retrieved" || pol.File != guid+"/Registry.pol" {
		t.Fatalf("Registry.pol %+v", pol)
	}
	if _, err := os.Stat(filepath.Join(root, guid, "Registry.pol")); err != nil {
		t.Fatal(err)
	}
	if xml := entry.Files["gpp_registry"]; xml.Status != "absent" {
		t.Fatalf("Registry.xml %+v", xml)
	}
}

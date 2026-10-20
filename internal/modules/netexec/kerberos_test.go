package netexec

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// AS-REP roasting and Kerberoasting are credential auditing, not exploitation:
// they ask the domain for material it hands to any authenticated account and
// write it into the assessment tree for offline auditing. They must be usable
// through the LDAP protocol - the protocol whose transport they inherit - and they
// must not be blocked by a policy gate.
func TestAsreproastAndKerberoastingBuildUsableCommands(t *testing.T) {
	runtime := testRuntime()
	cases := []struct {
		id     string
		flag   string
		output string
	}{
		{id: "asreproast", flag: "--asreproast", output: "asreproast.txt"},
		{id: "kerberoasting", flag: "--kerberoasting", output: "kerberoast.txt"},
	}
	for _, testCase := range cases {
		entry := findModule(t, testCase.id)
		if entry.Protocol() != modules.ProtocolLDAP {
			t.Fatalf("%s runs over %s, want LDAP", testCase.id, entry.Protocol())
		}
		if entry.Category() != modules.CategoryCredentialAuditing {
			t.Fatalf("%s is filed under %s, want Credential Auditing", testCase.id, entry.Category())
		}
		if !entry.ReadOnly() || entry.Sensitivity() != modules.SensitivitySensitive {
			t.Fatalf("%s does not describe itself as a read-only sensitive artifact", testCase.id)
		}
		args := entry.CommandArgs(runtime)
		if !slices.Contains(args, testCase.flag) {
			t.Fatalf("%s does not use %s: %#v", testCase.id, testCase.flag, args)
		}
		// The exported material has to land inside the assessment tree: the flag
		// takes a file, and NetExec rejects the command without one.
		index := slices.Index(args, testCase.flag)
		exported := args[index+1]
		want := filepath.Join(runtime.ResultsRoot, "CredentialAuditing", "NetExec", "LDAP_"+testCase.id, testCase.output)
		if exported != want {
			t.Fatalf("%s exports to %q, want %q", testCase.id, exported, want)
		}
		if !strings.HasPrefix(exported, runtime.ResultsRoot) {
			t.Fatalf("%s writes outside the assessment root: %s", testCase.id, exported)
		}
		// LDAPS stays the transport, and the credential is the operator's.
		if len(args) < 2 || args[len(args)-2] != "--port" || args[len(args)-1] != "636" {
			t.Fatalf("%s does not select LDAPS: %#v", testCase.id, args)
		}
		if !slices.Contains(args, runtime.Username) || !slices.Contains(args, runtime.Password) {
			t.Fatalf("%s does not pass the operator's credentials: %#v", testCase.id, args)
		}
		// A command without the export path is not a valid NetExec invocation, so
		// a runtime that cannot supply one reports unavailable instead of building
		// a flag whose value never arrived.
		withoutRoot := &modules.Runtime{Target: testTarget, Domain: testDomain, Username: "u", Password: "p"}
		if status := entry.Status(withoutRoot); status != modules.StatusUnavailable {
			t.Fatalf("%s reports %v without an assessment root", testCase.id, status)
		}
		if err := entry.Check(context.Background(), withoutRoot); err == nil {
			t.Fatalf("%s accepted a runtime with nowhere to write the exported material", testCase.id)
		}
	}
}

// The auditing registrations appear in the interface as available, with the
// artifact path visible in Module Information, and they are never swept into an
// enumeration run.
func TestAuditingRegistrationsAreAvailableAndSeparate(t *testing.T) {
	runtime := testRuntime()
	for _, id := range []string{"asreproast", "kerberoasting"} {
		entry := findModule(t, id)
		if status := entry.Status(runtime); status != modules.StatusAvailable {
			t.Fatalf("%s reports %v (%s); it is a supported auditing capability", id, status, entry.StatusReason(runtime))
		}
		details := strings.Join(entry.DetailLines(runtime), "\n")
		if !strings.Contains(details, "LDAP over LDAPS") {
			t.Fatalf("%s does not report its transport:\n%s", id, details)
		}
		if !strings.Contains(entry.Description(), "crack") {
			t.Fatalf("%s does not say what happens to the exported material", id)
		}
	}
	if modules.CategoriesForFamily(modules.ToolFamilyNetExec)[1] != modules.CategoryCredentialAuditing {
		t.Fatal("Credential Auditing is not offered for NetExec")
	}
}

// A capability the installed build does not advertise still reports unavailable,
// so enabling the auditing registrations does not assume they exist.
func TestAuditingRegistrationsRespectTheInstalledBuild(t *testing.T) {
	installFakeNXC(t, `#!/bin/sh
case "$1 $2" in
  "ldap --help") echo "--port --users"; exit 0 ;;
  "ldap -L") printf 'LOW PRIVILEGE MODULES\nENUMERATION\n[*] maq   Retrieves the MachineAccountQuota domain-level attribute\n'; exit 0 ;;
esac
exit 0
`)
	entry := findModule(t, "kerberoasting")
	entry.RefreshDetails(context.Background(), testRuntime())
	if status := entry.Status(testRuntime()); status != modules.StatusUnavailable {
		t.Fatalf("kerberoasting reports %v against a build without the flag", status)
	}
	if err := entry.Check(context.Background(), testRuntime()); err == nil {
		t.Fatal("Check accepted a flag the installed build does not advertise")
	}
}

// Modules with an obvious starting point are usable without configuration: a
// default is not a reason to show the operator an unavailable row.
func TestDefaultedOptionsKeepModulesAvailable(t *testing.T) {
	bare := &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret",
		ResultsRoot: "/tmp/pwnflow-results",
	}
	for _, id := range []string{"groupmembership", "smb-reg-query", "smb-wcc"} {
		entry := findModule(t, id)
		if status := entry.Status(bare); status == modules.StatusUnavailable {
			t.Fatalf("%s is unavailable without configuration: %s", id, entry.StatusReason(bare))
		}
	}
	// The dynamic defaults use the runtime, not a fixed string.
	group := findModule(t, "groupmembership")
	if args := group.CommandArgs(bare); !slices.Contains(args, "USER=audituser") {
		t.Fatalf("groupmembership does not default to the authenticated account: %#v", args)
	}
	runtimeDefault := false
	for _, argument := range findModule(t, "smb-wcc").CommandArgs(bare) {
		if strings.HasPrefix(argument, "OUTPUT=") && strings.HasPrefix(strings.TrimPrefix(argument, "OUTPUT="), bare.ResultsRoot) {
			runtimeDefault = true
		}
	}
	if !runtimeDefault {
		t.Fatalf("wcc does not default its report into the assessment tree: %#v", findModule(t, "smb-wcc").CommandArgs(bare))
	}
	// An operator value still wins over the default.
	override := &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret",
		ResultsRoot:   "/tmp/pwnflow-results",
		ModuleOptions: map[string]map[string]string{"groupmembership": {"USER": "someone-else"}},
	}
	if args := group.CommandArgs(override); !slices.Contains(args, "USER=someone-else") {
		t.Fatalf("the operator's value did not override the default: %#v", args)
	}
}

// Only the registrations that genuinely need an operator-supplied object are
// unavailable on a fresh run.
// A registration that only needs a value from the operator is configurable, not
// unsupported: it reports INPUT-REQ, and nothing in the registry reports
// UNAVAILABLE on a fresh run.
func TestOptionRequiringModulesAreConfigurableNotUnavailable(t *testing.T) {
	bare := &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret",
		ResultsRoot: "/tmp/pwnflow-results",
	}
	unavailable := make([]string, 0)
	configure := make([]string, 0)
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		switch entry.Status(bare) {
		case modules.StatusUnavailable:
			unavailable = append(unavailable, entry.ID())
		case modules.StatusInputRequired:
			configure = append(configure, entry.ID())
		}
	}
	slices.Sort(configure)
	want := []string{"daclread", "find-computer", "mssql-auth-check", "smb-spider-plus"}
	if strings.Join(configure, ",") != strings.Join(want, ",") {
		t.Fatalf("configurable registrations = %v, want exactly %v", configure, want)
	}
	if len(unavailable) != 0 {
		t.Fatalf("registrations report UNAVAILABLE on a fresh run: %v", unavailable)
	}
	// Every one of them is configurable, with the field the operator has to supply.
	for _, id := range want {
		entry := findModule(t, id)
		fields := entry.MissingInputs(bare)
		if len(fields) == 0 {
			t.Fatalf("%s reports INPUT-REQ without naming a field", id)
		}
		for _, field := range fields {
			if field.Prompt == "" {
				t.Fatalf("%s does not explain what %s is for", id, field.Key)
			}
		}
	}
	// Both become plainly available once the operator supplies what they need - by
	// typing it, or by passing --module-options.
	configured := &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret",
		ResultsRoot: "/tmp/pwnflow-results",
		ModuleOptions: map[string]map[string]string{
			"daclread":      {"TARGET": "Domain Admins"},
			"find-computer": {"TEXT": "SQL"},
		},
	}
	for _, id := range want {
		if status := findModule(t, id).Status(configured); status == modules.StatusUnavailable {
			t.Fatalf("%s is still unavailable after configuration: %s", id, findModule(t, id).StatusReason(configured))
		}
	}
}

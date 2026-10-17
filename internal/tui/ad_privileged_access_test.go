package tui

import (
	"strings"
	"testing"
	"time"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
)

func TestFormatADPrivilegedAccessIsDeterministicAndDoesNotExportSecrets(t *testing.T) {
	report := findingengine.GroupMembershipReport{
		Coverage: "Partial / not fully verified", GroupsExamined: 2, DirectEdges: 2, NestedRelationships: 1, UnresolvedReferences: 1,
		PrivilegedGroups: []findingengine.PrivilegedGroup{{Privilege: "Domain Admins", Name: "Domain Admins", Domain: "example.test", DirectMembers: []findingengine.GroupPrincipal{{ID: "S-1-5-21-1-2-3-901", Name: "svc-admin", Domain: "example.test", Type: "user", Disabled: true}}, NestedMembers: []findingengine.GroupPrincipal{{ID: "S-1-5-21-1-2-3-902", Name: "ops-user", Domain: "example.test", Type: "user", Path: []string{"Domain Admins", "Operations", "ops-user"}}}, Unresolved: []findingengine.GroupPrincipal{{ID: "S-1-5-21-9-9-9-1", Name: "S-1-5-21-9-9-9-1", Type: "unknown"}}}},
	}
	output := formatADPrivilegedAccess("/tmp/results", "example.test", time.Unix(1, 0), report)
	for _, expected := range []string{"PWNFLOW AD PRIVILEGED ACCESS INVENTORY", "Direct memberships observed:  2", "svc-admin [example.test] (disabled) (user)", "Domain Admins <- Operations <- ops-user"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in report:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "password") || strings.Contains(output, "hash") || strings.Contains(output, "token") {
		t.Fatalf("secret-like text leaked: %s", output)
	}
}

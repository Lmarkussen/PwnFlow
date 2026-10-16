package specialized

import (
	"context"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestModulesExposeOnlyBoundedModes(t *testing.T) {
	seen := map[string]bool{}
	for _, module := range Modules() {
		if seen[module.ID()] {
			t.Fatalf("duplicate module id %q", module.ID())
		}
		seen[module.ID()] = true
		if module.ID() == "sccmsecrets-offline" && module.ExecutionEnabled() {
			t.Fatal("SCCMSecrets live-capable registration was enabled")
		}
		if strings.Contains(module.CommandPreview(&modules.Runtime{Target: "10.0.0.42", Domain: "example.test", Username: "user", Password: "secret"}), "secret@") || strings.Contains(module.CommandPreview(&modules.Runtime{Target: "10.0.0.42", Domain: "example.test", Username: "user", Password: "secret"}), ":secret") {
			t.Fatalf("secret leaked in preview for %s", module.ID())
		}
	}
	for _, id := range []string{"mssqlrelay-check", "mssqlpwner-enumerate", "gpoparser-local", "gpoparser-remote", "ghostspn-audit", "sccmsecrets-offline"} {
		if !seen[id] {
			t.Fatalf("missing module %q", id)
		}
	}
}

func TestOfflineModuleRequiresExplicitPaths(t *testing.T) {
	for _, module := range Modules() {
		if module.ID() != "gpoparser-local" && module.ID() != "sccmsecrets-offline" {
			continue
		}
		missing := module.MissingInputs(&modules.Runtime{})
		if len(missing) == 0 {
			t.Fatalf("%s accepts no explicit artifact input", module.ID())
		}
		if err := module.Check(context.Background(), &modules.Runtime{Target: "dc", Domain: "example.test", Username: "user"}); err == nil {
			t.Fatalf("%s ran without its explicit input", module.ID())
		}
	}
}

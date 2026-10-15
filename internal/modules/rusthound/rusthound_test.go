package rusthound

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestRustHoundRegistrationAndControlledOutput(t *testing.T) {
	module := Module{}
	if module.ToolFamily() != modules.ToolFamilyActiveDirectory || module.Category() != modules.CategoryEnumeration || module.Protocol() != modules.ProtocolNA {
		t.Fatalf("unexpected taxonomy: %s/%s/%s", module.ToolFamily(), module.Category(), module.Protocol())
	}
	if module.ExecutionEnabled() || !strings.Contains(module.AvailabilityReason(), "scope restricted") {
		t.Fatal("RustHound-CE must remain scope restricted")
	}
	runtime := &modules.Runtime{ResultsRoot: "/tmp/pwnflow-results"}
	want := filepath.Join(runtime.ResultsRoot, "Enumeration", "RustHoundCE", "artifacts")
	if got := module.ArtifactDirectory(runtime); got != want {
		t.Fatalf("artifact directory=%q want %q", got, want)
	}
	if got := module.OutputFile(); got != "Enumeration/RustHoundCE/rusthound-ce.log" {
		t.Fatalf("log path=%q", got)
	}
}

func TestRustHoundCapabilityIsCheckedButScopeStillBlocksExecution(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "rusthound-ce")
	script := "#!/bin/sh\ncase \"$1\" in --help) echo '-d -u -p -i -o'; exit 0;; --version) echo 'rusthound-ce test'; exit 0;; esac\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	err := (Module{}).Check(context.Background(), &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain})
	if err == nil || !strings.Contains(err.Error(), "scope restricted") {
		t.Fatalf("unexpected capability/scope result: %v", err)
	}
}

func TestRustHoundRejectsUnauthorizedTargetBeforeCapabilityCheck(t *testing.T) {
	err := (Module{}).Check(context.Background(), &modules.Runtime{Target: "192.0.2.10", Domain: config.AuthorizedDomain})
	if err == nil || !strings.Contains(err.Error(), "outside the authorized assessment scope") {
		t.Fatalf("unexpected scope result: %v", err)
	}
}

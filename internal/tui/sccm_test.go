package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/sccm"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

// sccmResolver resolves the discovered names the fake tools report, so the test
// never touches DNS.
// sccmFamilyIndex is the SCCM row of the navigation pane.
const sccmFamilyIndex = 3

type sccmResolver map[string][]string

func (r sccmResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addresses, ok := r[host]; ok {
		return addresses, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

// sccmTooling installs fake SCCMhunter and PXEThief checkouts and returns the file
// that records every invocation. The fake tools behave like the real ones where the
// modules care: SCCMhunter prints its tables, PXEThief echoes its mode and target.
func sccmTooling(t *testing.T) string {
	t.Helper()
	tools := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", tools)
	record := filepath.Join(t.TempDir(), "invocations.log")
	t.Setenv("PWNFLOW_FAKE_RECORD", record)
	write := func(root, script, body string) {
		if err := os.MkdirAll(filepath.Join(tools, root, ".venv", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		interpreter := "#!/bin/sh\nscript=\"$1\"; shift\nprintf '%s %s\\n' \"$(basename \"$script\")\" \"$*\" >> \"$PWNFLOW_FAKE_RECORD\"\nexec /bin/sh -c \"$PWNFLOW_FAKE_BODY\" \"$0\" \"$@\"\n"
		if err := os.WriteFile(filepath.Join(tools, root, ".venv", "bin", "python3"), []byte(interpreter), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tools, root, script), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tools, root, "settings.ini"), []byte("auto_exploit_blank_password = 0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The help shape mirrors the installed tools: SCCMhunter documents its
	// subcommands at the top level and the find options on the subcommand, and
	// PXEThief prints its usage for -h. A probe that reads the wrong one would
	// reject a working installation.
	t.Setenv("PWNFLOW_FAKE_BODY", `case "$1" in
--help) echo "Usage: sccmhunter [OPTIONS] COMMAND [ARGS]..."; echo "  find  Enumerate LDAP for SCCM assets."; echo "  show  Show and/or recon table results."; exit 0 ;;
-h) echo "pxethief.py 1"; echo "pxethief.py 2 <ip>"; exit 0 ;;
find)
  if [ "$2" = "--help" ]; then echo "Options: -u -p -d -dc-ip -ldaps"; exit 0; fi
  echo "Potential PXE Distribution Points"; echo "+---------------------+"; echo "| Hostname            |"; echo "+---------------------+"; echo "| pxe01.example.test  |"; exit 0 ;;
show) echo "Management Points Table"; echo "+---------------------+"; echo "| Hostname            |"; echo "+---------------------+"; echo "| mp01.example.test   |"; echo "Potential PXE Distribution Points"; echo "+---------------------+"; echo "| Hostname            |"; echo "+---------------------+"; echo "| pxe01.example.test  |"; exit 0 ;;
1) echo "[+] mode 1 broadcast"; exit 0 ;;
2) echo "[+] mode 2 against $2"; exit 0 ;;
esac
exit 1`)
	write("sccmhunter", "sccmhunter.py", "# fake sccmhunter\n")
	write("PXEThief", "pxethief.py", "# fake pxethief\n")
	// The required revision is verified against the checkout's HEAD, so the fake
	// checkout is a real repository whose recorded revision is its own.
	if output, err := exec.Command("git", "-C", filepath.Join(tools, "PXEThief"), "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	for _, args := range [][]string{{"-C", filepath.Join(tools, "PXEThief"), "add", "-A"}, {"-C", filepath.Join(tools, "PXEThief"), "-c", "user.email=t@example.test", "-c", "user.name=test", "commit", "-qm", "pull/11"}} {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, output)
		}
	}
	head, err := exec.Command("git", "-C", filepath.Join(tools, "PXEThief"), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "PXEThief", ".pwnflow-pr11"), head, 0o600); err != nil {
		t.Fatal(err)
	}
	return record
}

// The SCCM family is a first-class navigation scope with both modules registered
// under Enumeration, and YOLO stays limited to NetExec.
func TestSCCMFamilyIsRegisteredAndScoped(t *testing.T) {
	sccmTooling(t)
	registered := []modules.Module{sccm.SCCMHunter{Resolver: sccmResolver{}}, sccm.PXEThief{}}
	m := newModel(context.Background(), config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Root: t.TempDir()}, nil, registered, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()

	family := -1
	for index, candidate := range m.toolFamilies {
		if candidate == modules.ToolFamilySCCM {
			family = index
		}
	}
	if family < 0 {
		t.Fatalf("SCCM is not a tool family: %v", m.toolFamilies)
	}
	m.setToolFamily(family)
	if len(m.modules) != 2 {
		t.Fatalf("both SCCM modules must be visible: %v", moduleIDs(m.modules))
	}
	if m.categories[m.categoryIndex] != modules.CategoryEnumeration {
		t.Fatalf("unexpected category: %v", m.categories)
	}
	for index := range m.modules {
		if state := m.moduleState(index); state != "READY" {
			t.Fatalf("installed SCCM tooling must be READY, got %q for %s", state, m.modules[index].ID())
		}
		if reason := m.moduleAvailability(m.modules[index]); reason != "" {
			t.Fatalf("%s is unavailable although it is installed: %q", m.modules[index].ID(), reason)
		}
	}
	// A stays scoped: the SCCM scope is not NetExec enumeration.
	m.focus = focusModules
	press(t, m, "a")
	if m.batch != nil {
		t.Fatalf("YOLO started outside NetExec enumeration: %v", batchIDs(m))
	}
}

// Selecting both SCCM modules and pressing R discovers first and probes afterwards,
// and PXEThief uses the endpoints the same run discovered.
func TestSCCMDiscoveryFeedsPXEThiefInOneBatch(t *testing.T) {
	record := sccmTooling(t)
	database, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registered := []modules.Module{sccm.SCCMHunter{Resolver: sccmResolver{"pxe01.example.test": {"198.51.100.41"}, "mp01.example.test": {"198.51.100.42"}}}, sccm.PXEThief{}}
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret", Root: t.TempDir()}
	m := newModel(context.Background(), cfg, database, registered, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules

	for _, id := range []string{"sccmhunter", "pxethief"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}
	press(t, m, "r")
	if got := strings.Join(batchIDs(m), ","); got != "sccmhunter,pxethief" {
		t.Fatalf("the batch must discover before it probes: %s", got)
	}
	waitForBatch(t, m)
	contents, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(contents)), "\n")
	var workflow []string
	for _, invocation := range invocations {
		if strings.HasSuffix(invocation, " --help") || strings.HasSuffix(invocation, " -h") {
			continue
		}
		workflow = append(workflow, invocation)
	}
	joined := strings.Join(workflow, " | ")
	if !strings.Contains(joined, "sccmhunter.py find") || !strings.Contains(joined, "sccmhunter.py show -all") {
		t.Fatalf("discovery did not run its workflow: %s", joined)
	}
	if !strings.Contains(joined, "pxethief.py 2 198.51.100.41") || !strings.Contains(joined, "pxethief.py 2 198.51.100.42") {
		t.Fatalf("PXEThief did not probe the freshly discovered endpoints: %s", joined)
	}
	if strings.Index(joined, "sccmhunter.py find") > strings.Index(joined, "pxethief.py 2") {
		t.Fatalf("PXEThief ran before discovery finished: %s", joined)
	}
	if strings.Contains(joined, "pxethief.py 1") {
		t.Fatalf("the zero-endpoint fallback was used although endpoints were discovered: %s", joined)
	}
}

// The ordering mechanism holds however the modules are ordered in the registry.
func TestBatchOrderingHonoursDeclaredPrerequisites(t *testing.T) {
	probe := runner.BatchItem{Index: 0, Module: sccm.PXEThief{}}
	discover := runner.BatchItem{Index: 1, Module: sccm.SCCMHunter{}}
	ordered := orderBatch([]runner.BatchItem{probe, discover})
	if ordered[0].Module.ID() != "sccmhunter" || ordered[1].Module.ID() != "pxethief" {
		t.Fatalf("the declared prerequisite was not honoured: %v", []string{ordered[0].Module.ID(), ordered[1].Module.ID()})
	}
}

// Module Information reports the SCCM configuration the operator needs: the
// dependency, the mode PXEThief would use, and where its artifacts go.
func TestSCCMModuleInformation(t *testing.T) {
	sccmTooling(t)
	database, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registered := []modules.Module{sccm.SCCMHunter{Resolver: sccmResolver{}}, sccm.PXEThief{}}
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Root: t.TempDir()}
	m := newModel(context.Background(), cfg, database, registered, []int64{1, 2}, 1, "test")
	m.width, m.height = 170, 54
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)

	m.cursor = rowOf(t, m, "sccmhunter")
	frame := renderFrame(m)
	for _, want := range []string{"SCCMhunter: installed", "find then show -all over LDAPS", "Discovered endpoints:", "Discovery output directory:"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("SCCMhunter information is missing %q:\n%s", want, frame)
		}
	}
	m.cursor = rowOf(t, m, "pxethief")
	frame = renderFrame(m)
	for _, want := range []string{"Required revision: pull/11 verified", "Planned mode: mode 1", "Artifacts:"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("PXEThief information is missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "Sup3rSecret") {
		t.Fatal("Module Information leaked a credential")
	}
}

package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

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
	// An approved run executes through sudo. The stand-in records that it was used and
	// then runs the command it was given, so no real sudo and no real elevation is
	// involved; the rest of PATH stays available for the checkout's own git calls.
	sudoBin := t.TempDir()
	sudo := "#!/bin/sh\n" +
		"printf '%s\\n' \"sudo $*\" >> \"" + record + "\"\n" +
		"while [ \"${1#-}\" != \"$1\" ]; do shift; done\n" +
		"exec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(sudoBin, "sudo"), []byte(sudo), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", sudoBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return record
}

// The SCCM family is a first-class navigation scope. Default Enumeration keeps
// PXEThief behind its specific local-sudo authorization rather than the old
// blanket approval panel.
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
		if state := m.moduleState(index); state != "" {
			t.Fatalf("installed SCCM tooling must carry no status suffix, got %q for %s", state, m.modules[index].ID())
		}
		if reason := m.moduleAvailability(m.modules[index]); reason != "" {
			t.Fatalf("%s is unavailable although it is installed: %q", m.modules[index].ID(), reason)
		}
	}
	// Default Enumeration includes the curated SCCM discovery module, but does not
	// launch PXEThief without its specific authorization.
	m.focus = focusModules
	press(t, m, "a")
	if m.batch == nil || !contains(batchIDs(m), "sccmhunter") || contains(batchIDs(m), "pxethief") {
		t.Fatalf("unexpected Default Enumeration SCCM batch: %v", batchIDs(m))
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
	stubSudo(t, nil)

	for _, id := range []string{"sccmhunter", "pxethief"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}
	press(t, m, "r")
	approveElevationIfAsked(t, m)
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
	refreshDetails(t, m)

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

// refreshDetails runs the Module Information refresh the ticker issues, so a test can
// assert what the pane shows once the snapshot has been collected off the render path.
func refreshDetails(t *testing.T, m *model) {
	t.Helper()
	m.detailsRefreshed = time.Time{}
	command := m.refreshDetailsCommand()
	if command == nil {
		return
	}
	if msg := command(); msg != nil {
		m.Update(msg)
	}
}

// approveElevation answers the elevation prompt the way the operator does, so a test
// about another behaviour is not affected by whether the host has CAP_NET_RAW.
// stubSudo replaces the terminal handover with one that answers immediately, and
// returns a counter of how often the operator was asked to authenticate.
func stubSudo(t *testing.T, err error) *int {
	t.Helper()
	previous := sudoAuthenticate
	calls := 0
	sudoAuthenticate = func(*exec.Cmd) tea.Cmd {
		calls++
		return func() tea.Msg { return sudoAuthorisedMsg{err: err} }
	}
	t.Cleanup(func() { sudoAuthenticate = previous })
	return &calls
}

func approveElevationIfAsked(t *testing.T, m *model) {
	t.Helper()
	if !m.elevationPrompt {
		return
	}
	updated, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if cmd == nil {
		t.Fatal("approving elevation produced no authentication command")
	}
	if msg := cmd(); msg != nil {
		updated.(*model).Update(msg)
	}
}

// elevatingModule is a module that needs privileges, records its execution, and lets
// a test drive the approval flow without a real terminal or a real sudo.
type elevatingModule struct {
	selectionModule
	required bool
}

func (m elevatingModule) ElevationRequired() (bool, string) {
	if m.required {
		return true, "this module needs raw-socket privileges"
	}
	return false, ""
}

// The elevation prompt appears once for a batch, an answer other than "y" declines,
// and the modules that do not need privileges still run.
func TestElevationPromptDeclinesSafelyAndRunsTheRest(t *testing.T) {
	log := &executionLog{}
	elevating := elevatingModule{selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	plain := selectionModule{id: "plain", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{elevating, plain}, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules
	for _, id := range []string{"needs-privileges", "plain"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}

	press(t, m, "r")
	if !m.elevationPrompt || m.batch != nil {
		t.Fatalf("the batch started without asking for elevation: prompt=%v batch=%v", m.elevationPrompt, m.batch)
	}
	if !strings.Contains(m.status, "sudo") || !strings.Contains(m.status, "y/N") {
		t.Fatalf("the question is not clear: %q", m.status)
	}

	// Any other key declines: it must not start the privileged module.
	press(t, m, "n")
	if m.elevationPrompt || m.batch == nil || !m.running {
		t.Fatalf("declining did not clear the prompt and run the rest: prompt=%v running=%v", m.elevationPrompt, m.running)
	}
	declinedStatus := m.status
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "plain" {
		t.Fatalf("declining did not run exactly the unprivileged module: %v", got)
	}
	if !strings.Contains(declinedStatus, "not approved") {
		t.Fatalf("the refusal was not reported: %q", declinedStatus)
	}
	// The selection survives the whole exchange.
	if selected := m.selectedCount(); selected != 2 {
		t.Fatalf("the selection changed: %d", selected)
	}
}

// Pressing "y" hands the terminal to sudo once, and only the module that asked for
// elevation is approved for that run.
func TestElevationApprovalAppliesToTheRequestedRunOnly(t *testing.T) {
	log := &executionLog{}
	elevating := elevatingModule{selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	plain := selectionModule{id: "plain", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	other := selectionModule{id: "other", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{elevating, plain, other}, []int64{1, 2, 3}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules
	for _, id := range []string{"needs-privileges", "plain"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}

	prompts := stubSudo(t, nil)

	press(t, m, "r")
	approveElevationIfAsked(t, m)
	if *prompts != 1 {
		t.Fatalf("sudo was asked for %d times, want once per requested run", *prompts)
	}
	if got := batchIDs(m); strings.Join(got, ",") != "needs-privileges,plain" {
		t.Fatalf("the approved batch is wrong: %v", got)
	}
	if !m.ElevationApproved("needs-privileges") || m.ElevationApproved("plain") {
		t.Fatal("approval did not stay scoped to the module that needed it")
	}
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "needs-privileges,plain" {
		t.Fatalf("unexpected execution: %v", got)
	}
	// The approval is for the requested run: the next selection asks again.
	if m.ElevationApproved("needs-privileges") {
		t.Fatal("the approval outlived the run it was given for")
	}
	m.batch, m.batchItems, m.running = nil, nil, false
	m.selectedModules = map[string]bool{"needs-privileges": true, "other": true}
	press(t, m, "r")
	if !m.elevationPrompt {
		t.Fatal("a later run did not ask for elevation again")
	}
	press(t, m, "n")
	waitForBatch(t, m)
}

// A refused or cancelled sudo authentication skips the privileged module, keeps the
// rest of the batch, and leaves the interface usable.
func TestElevationFailureSkipsOnlyThePrivilegedModule(t *testing.T) {
	log := &executionLog{}
	elevating := elevatingModule{selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	plain := selectionModule{id: "plain", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{elevating, plain}, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules
	for _, id := range []string{"needs-privileges", "plain"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}
	previous := sudoAuthenticate
	sudoAuthenticate = func(*exec.Cmd) tea.Cmd {
		return func() tea.Msg { return sudoAuthorisedMsg{err: errors.New("sudo: 3 incorrect password attempts")} }
	}
	t.Cleanup(func() { sudoAuthenticate = previous })

	press(t, m, "r")
	approveElevationIfAsked(t, m)
	failureStatus := m.status
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "plain" {
		t.Fatalf("a failed authentication did not skip only the privileged module: %v", got)
	}
	if !strings.Contains(failureStatus, "authentication failed") {
		t.Fatalf("the authentication failure was not reported: %q", failureStatus)
	}
	if m.elevationPrompt || m.running {
		t.Fatal("the interface was left in the prompt or running state")
	}
	// The TUI is still usable: navigation and selection keep working.
	m.cursor = rowOf(t, m, "plain")
	press(t, m, " ")
	if m.selectedModules["plain"] {
		t.Fatal("selection stopped working after a failed authentication")
	}
}

// Every entry point that can start PXEThief goes through the same approval gate: the
// global selection with R, the highlighted module with Enter, and the global plan
// with A, which reaches it from any scope and therefore asks for the privilege
// rather than starting a DHCP broadcast or a privileged run by itself.
func TestEveryEntryPointRequiresApprovalForPXEThief(t *testing.T) {
	log := &executionLog{}
	elevating := elevatingModule{selectionModule: selectionModule{id: "pxethief-like", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	netexecModule := selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{elevating, netexecModule}, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules

	// Enter on the highlighted module.
	m.cursor = rowOf(t, m, "pxethief-like")
	press(t, m, "enter")
	if !m.elevationPrompt || m.running {
		t.Fatalf("Enter started a privileged module without asking: prompt=%v running=%v", m.elevationPrompt, m.running)
	}
	press(t, m, "n")
	if got := log.executed(); len(got) != 0 {
		t.Fatalf("declining Enter still ran the module: %v", got)
	}

	// The global batch with R.
	m.cursor = rowOf(t, m, "pxethief-like")
	press(t, m, " ")
	press(t, m, "r")
	if !m.elevationPrompt || m.running {
		t.Fatalf("R started a privileged module without asking: prompt=%v running=%v", m.elevationPrompt, m.running)
	}
	press(t, m, "n")
	if m.batch != nil || m.running {
		t.Fatalf("declining R started something: running=%v", m.running)
	}
	if got := log.executed(); len(got) != 0 {
		t.Fatalf("declining R still ran the module: %v", got)
	}

	// A covers the whole registry, so it reaches the privileged module and has to
	// ask for it too - from a NetExec scope, and without the operator selecting
	// anything.
	m.batch, m.batchItems, m.running = nil, nil, false
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	press(t, m, "a")
	if !m.elevationPrompt || m.running {
		t.Fatalf("A started a privileged module without asking: prompt=%v running=%v", m.elevationPrompt, m.running)
	}
	press(t, m, "n")
	// Declining skips the privileged module and runs the rest of the plan.
	if !m.running {
		t.Fatalf("declining the privileged module left nothing to run: %q", m.status)
	}
	waitForBatch(t, m)
	if got := log.executed(); len(got) != 1 || got[0] != "nxc-ldap-users" {
		t.Fatalf("the rest of the plan did not run: %v", got)
	}
	// The privileged module stayed unexecuted: the plan's own approval and the
	// sudo confirmation are both required, and it received neither.
	for _, id := range log.executed() {
		if id == "pxethief-like" {
			t.Fatal("the privileged module ran without approval")
		}
	}
}

// Navigation must not run the tools' capability probes: the expensive work belongs to
// the refresh, and the refresh is skipped while the snapshot is fresh.
func TestNavigationDoesNotProbeTheTools(t *testing.T) {
	record := sccmTooling(t)
	database, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registered := []modules.Module{sccm.SCCMHunter{Resolver: sccmResolver{"pxe01.example.test": {"198.51.100.41"}}}, sccm.PXEThief{}}
	m := newModel(context.Background(), testConfig(t), database, registered, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules
	refreshDetails(t, m)

	countInvocations := func() int {
		contents, readErr := os.ReadFile(record)
		if readErr != nil {
			return 0
		}
		lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			return 0
		}
		return len(lines)
	}
	before := countInvocations()
	if before == 0 {
		t.Fatal("the initial refresh did not probe the tool, so this test would prove nothing")
	}

	start := time.Now()
	for i := 0; i < 40; i++ {
		m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
		_ = m.View()
		m.handleKey(tea.KeyMsg{Type: tea.KeyUp})
		_ = m.View()
	}
	elapsed := time.Since(start)
	if after := countInvocations(); after != before {
		t.Fatalf("navigation probed the tools: %d invocations before, %d after", before, after)
	}
	if perFrame := elapsed / 80; perFrame > 20*time.Millisecond {
		t.Fatalf("a frame took %v, which means work is still on the render path", perFrame)
	}
}

// Module Information is filled by the refresh, not by rendering.
func TestModuleInformationComesFromTheSnapshot(t *testing.T) {
	sccmTooling(t)
	database, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registered := []modules.Module{sccm.SCCMHunter{Resolver: sccmResolver{}}, sccm.PXEThief{}}
	m := newModel(context.Background(), testConfig(t), database, registered, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)

	// Before any refresh the pane says so instead of probing.
	if frame := renderFrame(m); !strings.Contains(frame, "being collected") {
		t.Fatalf("the pane probed before a refresh:\n%s", frame)
	}
	refreshDetails(t, m)
	m.cursor = rowOf(t, m, "sccmhunter")
	if frame := renderFrame(m); !strings.Contains(frame, "SCCMhunter: installed") {
		t.Fatalf("the refresh did not fill the pane:\n%s", frame)
	}
}

// BenchmarkSCCMNavigationFrame measures one rendered frame in the SCCM scope, which is
// the cost an arrow key pays.
func BenchmarkSCCMNavigationFrame(b *testing.B) {
	tools := b.TempDir()
	os.Setenv("PWNFLOW_TOOLS_DIR", tools)
	for _, tool := range []struct{ root, script string }{{"sccmhunter", "sccmhunter.py"}, {"PXEThief", "pxethief.py"}} {
		if err := os.MkdirAll(filepath.Join(tools, tool.root, ".venv", "bin"), 0o755); err != nil {
			b.Fatal(err)
		}
		interpreter := "#!/bin/sh\ncase \"$1\" in\n--help) echo \"Commands:\"; echo \"  find\"; echo \"  show\"; exit 0 ;;\nfind) echo \"-u -p -d -dc-ip -ldaps\"; exit 0 ;;\n-h) echo \"pxethief.py 1\"; exit 0 ;;\nesac\nexit 0\n"
		if err := os.WriteFile(filepath.Join(tools, tool.root, ".venv", "bin", "python3"), []byte(interpreter), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tools, tool.root, tool.script), []byte("# entry\n"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	registered := []modules.Module{sccm.SCCMHunter{}, sccm.PXEThief{}}
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret", Root: b.TempDir()}
	model := newModel(context.Background(), cfg, nil, registered, []int64{1, 2}, 1, "bench")
	model.width, model.height = 170, 54
	model.resizeOutput()
	model.setToolFamily(sccmFamilyIndex)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = model.View()
	}
}

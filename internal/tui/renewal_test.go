package tui

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// stubSudoAuthentication replaces the terminal handoff with a recorded outcome, so
// a test can drive the approval flow without a terminal.
func stubSudoAuthentication(t *testing.T, err error) *int {
	t.Helper()
	calls := new(int)
	previous := sudoAuthenticate
	sudoAuthenticate = func(*exec.Cmd) tea.Cmd {
		*calls++
		return func() tea.Msg { return sudoAuthorisedMsg{err: err} }
	}
	t.Cleanup(func() { sudoAuthenticate = previous })
	return calls
}

// awaitRenewalPrompt runs the interface loop until a waiting module's renewal is
// on screen, which is what the tick does for the operator.
func awaitRenewalPrompt(t *testing.T, m *model) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m.Update(tickMsg(time.Now()))
		if m.elevationPrompt && m.renewing {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a waiting module never reached the operator")
}

// answerRenewalPress sends one key through the real handler and runs the command it
// returns, which is how the operator answers.
func answerRenewalPress(t *testing.T, m *model, key string) {
	t.Helper()
	_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	if command == nil {
		return
	}
	if msg := command(); msg != nil {
		m.Update(msg)
	}
}

// A module that finds sudo's authorization expired asks here, at its own boundary,
// and the operator answers with the same amber confirmation the batch preflight
// uses. Approving releases the terminal for sudo and unblocks the module.
func TestExpiredSudoAuthorizationIsRenewedThroughTheOperator(t *testing.T) {
	m := statusModel(t, []modules.Module{
		statusModule{id: "pxethief", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, status: modules.StatusAvailable, execution: true},
		statusModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, status: modules.StatusAvailable, execution: true},
	})
	calls := stubSudoAuthentication(t, nil)

	result := make(chan bool, 1)
	go func() {
		result <- m.RenewElevation(context.Background(), "pxethief", "PXEThief needs local sudo privileges")
	}()
	awaitRenewalPrompt(t, m)

	if !strings.Contains(m.status, "sudo authorization expired") || !strings.Contains(m.status, "PXEThief needs local sudo privileges") {
		t.Fatalf("the renewal prompt does not explain itself: %q", m.status)
	}
	if m.statusHeaderStyle().GetForeground() != warn.GetForeground() {
		t.Fatal("the renewal prompt is not shown in the confirmation colour")
	}
	if frame := ansi.Strip(m.View()); !strings.Contains(frame, "NAVIGATION") {
		t.Fatalf("the interface stopped rendering while a module waited:\n%s", frame)
	}

	answerRenewalPress(t, m, "y")
	if approved := <-result; !approved {
		t.Fatal("the operator approved but the module was told no")
	}
	if *calls != 1 {
		t.Fatalf("the terminal was released %d time(s), want once", *calls)
	}
	if m.elevationPrompt || m.renewing {
		t.Fatal("the prompt stayed open after the answer")
	}
	if m.running {
		t.Fatal("a renewal started a batch; the running one continues on its own")
	}
	// The interface is untouched otherwise: the module list still navigates.
	if len(m.modules) == 0 {
		t.Fatal("the visible module list disappeared")
	}
	press(t, m, "down")
	if frame := ansi.Strip(m.View()); !strings.Contains(frame, "ENUMERATION MODULES") {
		t.Fatalf("the module pane stopped rendering after the renewal:\n%s", frame)
	}
}

// Declining the renewal tells the module no, and nothing privileged runs.
func TestDeclinedRenewalLeavesTheModuleWithoutAuthorization(t *testing.T) {
	m := statusModel(t, nil)
	calls := stubSudoAuthentication(t, nil)
	result := make(chan bool, 1)
	go func() {
		result <- m.RenewElevation(context.Background(), "pxethief", "PXEThief needs local sudo privileges")
	}()
	awaitRenewalPrompt(t, m)

	answerRenewalPress(t, m, "n")
	if approved := <-result; approved {
		t.Fatal("declining the renewal still authorized the module")
	}
	if *calls != 0 {
		t.Fatal("declining the renewal still asked for a password")
	}
	if !strings.Contains(m.status, "not renewed") {
		t.Fatalf("the refusal was not explained: %q", m.status)
	}
}

// Escape answers the same way as "n": no authorization, and the batch continues.
func TestEscapeDeclinesTheRenewal(t *testing.T) {
	m := statusModel(t, nil)
	stubSudoAuthentication(t, nil)
	result := make(chan bool, 1)
	go func() { result <- m.RenewElevation(context.Background(), "pxethief", "reason") }()
	awaitRenewalPrompt(t, m)

	_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if command != nil {
		t.Fatal("Escape started something instead of declining")
	}
	if approved := <-result; approved {
		t.Fatal("Escape authorized the module")
	}
	if m.elevationPrompt {
		t.Fatal("the prompt stayed open")
	}
}

// A failed authentication is a refusal, not an authorization.
func TestFailedRenewalAuthenticationDeclinesTheModule(t *testing.T) {
	m := statusModel(t, nil)
	stubSudoAuthentication(t, errors.New("sudo: 3 incorrect password attempts"))
	result := make(chan bool, 1)
	go func() { result <- m.RenewElevation(context.Background(), "pxethief", "reason") }()
	awaitRenewalPrompt(t, m)

	answerRenewalPress(t, m, "y")
	if approved := <-result; approved {
		t.Fatal("a failed authentication authorized the module")
	}
	if !strings.Contains(m.status, "failed") {
		t.Fatalf("the failure was not reported: %q", m.status)
	}
}

// Cancelling while a module waits for an answer tells it no, so the batch can
// finish instead of hanging on a question nobody will answer.
func TestCancellingTheRunAnswersTheWaitingModule(t *testing.T) {
	m := statusModel(t, nil)
	stubSudoAuthentication(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- m.RenewElevation(ctx, "pxethief", "reason") }()
	awaitRenewalPrompt(t, m)

	cancel()
	if approved := <-result; approved {
		t.Fatal("a cancelled run authorized the module")
	}
}

// The batch preflight asks once, before anything runs, and names what needs it.
func TestBatchPreflightAsksForSudoBeforeStarting(t *testing.T) {
	privileged := elevatingModule{
		selectionModule: selectionModule{id: "pxethief-like", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: &executionLog{}},
		required:        true,
	}
	plain := selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: &executionLog{}}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{privileged, plain}, []int64{1, 2}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	calls := stubSudoAuthentication(t, nil)

	press(t, m, "a")
	if !m.elevationPrompt || m.running {
		t.Fatalf("the privileged plan started without asking: prompt=%v running=%v", m.elevationPrompt, m.running)
	}
	if !strings.Contains(m.status, "local sudo privileges") || !strings.Contains(m.status, "Authenticate with sudo before starting") {
		t.Fatalf("the preflight does not say what it wants: %q", m.status)
	}
	answerRenewalPress(t, m, "n")
	if !m.running {
		t.Fatalf("declining left nothing to run: %q", m.status)
	}
	if *calls != 0 {
		t.Fatal("declining still asked for a password")
	}
	waitForBatch(t, m)
	if got := privileged.log.executed(); len(got) != 0 {
		t.Fatalf("the declined module ran: %v", got)
	}
}

// A plan with nothing privileged never asks.
func TestUnprivilegedPlanNeverAsksForSudo(t *testing.T) {
	m := statusModel(t, []modules.Module{
		selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: &executionLog{}},
	})
	calls := stubSudoAuthentication(t, nil)
	press(t, m, "a")
	if m.elevationPrompt {
		t.Fatal("an unprivileged plan asked for sudo")
	}
	if !m.running {
		t.Fatalf("the plan did not start: %q", m.status)
	}
	if *calls != 0 {
		t.Fatal("the terminal was released for an unprivileged plan")
	}
	waitForBatch(t, m)
}

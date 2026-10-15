package tui

import (
	"context"
	"time"
)

// Sudo authorization renewal, mid-batch.
//
// The operator approves elevation for one batch, before it starts. sudo caches
// that authentication with a lifetime of its own, and a long batch can outlive it.
// Rather than let a privileged tool fail on the target, or let sudo prompt where
// nobody can see it, a module that is about to run privileged work asks the model
// for a renewal: the request arrives here, the batch is already paused at that
// boundary, and the answer is only "yes" once the terminal has been released for
// sudo's own prompt and the model has handed it back.
//
// The password never passes through PwnFlow: sudo reads it from the terminal
// during the handoff, exactly as it does for the initial approval.

// renewalRequest is one module's request, with the channel it waits on.
type renewalRequest struct {
	moduleID string
	reason   string
	reply    chan bool
}

// PendingRenewal is implemented by the model for the refresh loop: it reports a
// waiting module and the prompt it should show, if any.
func (m *model) nextRenewal() (renewalRequest, bool) {
	if m.elevationRenewal == nil {
		return renewalRequest{}, false
	}
	select {
	case request := <-m.elevationRenewal:
		return request, true
	default:
		return renewalRequest{}, false
	}
}

// requestRenewalPrompt puts a waiting module's renewal in front of the operator,
// reusing the amber confirmation the initial approval uses.
func (m *model) requestRenewalPrompt(request renewalRequest) {
	m.renewalReply = request.reply
	m.renewing = true
	m.renewalModule = request.moduleID
	m.elevationPrompt = true
	m.elevationModules = []string{request.moduleID}
	m.status = request.reason + ". sudo authorization expired; authenticate again to continue? [y/N]"
}

// RenewElevation implements modules.ElevationPolicy. It blocks the calling module
// until the operator has answered, and returns false whenever PwnFlow could not
// obtain a fresh authorization - a refusal, a cancelled handoff, a failed
// authentication, or a context that ended first.
func (m *model) RenewElevation(ctx context.Context, moduleID, reason string) bool {
	if m.elevationRenewal == nil {
		return false
	}
	reply := make(chan bool, 1)
	select {
	case m.elevationRenewal <- renewalRequest{moduleID: moduleID, reason: reason, reply: reply}:
	case <-ctx.Done():
		return false
	case <-time.After(renewalRequestTimeout):
		return false
	}
	select {
	case approved := <-reply:
		return approved
	case <-ctx.Done():
		return false
	case <-time.After(renewalAnswerTimeout):
		return false
	}
}

// renewalRequestTimeout bounds how long a module waits for the loop to notice its
// request, and renewalAnswerTimeout how long it waits for the operator. Both are
// generous: the operator may be reading the prompt.
var (
	renewalRequestTimeout = 5 * time.Second
	renewalAnswerTimeout  = 10 * time.Minute
)

// answerRenewal releases the waiting module. A nil reply channel means the request
// was already answered, which happens when the batch was cancelled underneath it.
func (m *model) answerRenewal(approved bool) {
	if m.renewalReply == nil {
		return
	}
	reply := m.renewalReply
	m.renewalReply = nil
	m.renewing = false
	m.renewalModule = ""
	select {
	case reply <- approved:
	default:
	}
}

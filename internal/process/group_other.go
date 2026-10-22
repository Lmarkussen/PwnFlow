//go:build !unix

package process

import "os/exec"

// configure is a no-op where process groups are not part of the model. PwnFlow
// supports Kali as its installation target; this keeps the package buildable and
// the termination honest rather than silently different.
func configure(command *exec.Cmd) {}

// terminate stops the process itself. Without process groups there is nothing
// wider to address, and the escalation is still ordered.
func terminate(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
}

func forceKill(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
}

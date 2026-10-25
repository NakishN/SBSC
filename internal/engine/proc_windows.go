//go:build windows

package engine

import (
	"os/exec"
	"syscall"
)

// hideConsole prevents child tools such as java.exe, javap.exe, objdump.exe and
// dumpbin.exe from opening a console window. The scanner captures their stdout
// and stderr, so no console is needed.
func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	// CREATE_NO_WINDOW is the strongest guarantee on Windows, including when
	// the parent is a GUI-subsystem process.
	cmd.SysProcAttr.CreationFlags |= 0x08000000
}

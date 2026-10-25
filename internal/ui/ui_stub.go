//go:build !windows

package ui

import (
	"fmt"
	"os"

	"sbsc/internal/engine"
)

// Run is only available on Windows; other platforms use the CLI.
func Run(opts engine.Options, paths []string) error {
	return fmt.Errorf("GUI доступен только в Windows-сборке; используйте --cli")
}

// AcquireSingleInstance is a no-op outside Windows.
func AcquireSingleInstance() bool { return true }

// ShowError falls back to stderr outside Windows.
func ShowError(title, msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, msg)
}

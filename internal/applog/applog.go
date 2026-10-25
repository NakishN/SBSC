// Package applog writes a small startup log. The Windows GUI has no console,
// so this is the only way to see why the window failed to appear.
package applog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var mu sync.Mutex

// Path returns the log location. On Windows this is
// %LOCALAPPDATA%\SBSC\startup.log.
func Path() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "SBSC", "startup.log")
	}
	if cache, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cache, "SBSC", "startup.log")
	}
	return filepath.Join(os.TempDir(), "SBSC-startup.log")
}

// Write appends one line to the startup log. Errors are deliberately ignored:
// logging must never prevent the scanner from starting.
func Write(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()

	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

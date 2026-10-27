//go:build !linux && !windows

package engine

// systemMemory is unavailable on this platform; the caller falls back to
// CPU-count-only tuning.
func systemMemory() (total, available uint64) {
	return 0, 0
}

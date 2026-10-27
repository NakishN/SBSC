//go:build linux

package engine

import (
	"os"
	"strconv"
	"strings"
)

// systemMemory returns total and currently available physical memory. Linux
// exposes MemAvailable, which already accounts for reclaimable page cache.
func systemMemory() (total, available uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var free, buffers, cached uint64
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		v *= 1024
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			available = v
		case "MemFree:":
			free = v
		case "Buffers:":
			buffers = v
		case "Cached:":
			cached = v
		}
	}
	if available == 0 {
		available = free + buffers + cached
	}
	return total, available
}

package engine

import (
	"os"
	"runtime"
	"runtime/debug"
)

const (
	// A single large JAR can allocate hundreds of MB while its classes are
	// parsed. Files above this limit are additionally serialized.
	bigFileThreshold = int64(64 << 20)
	// Conservative per-worker memory budget used for automatic tuning.
	workerMemoryBudget = uint64(768 << 20)
	minimumMemoryLimit = int64(256 << 20)
)

type systemTuning struct {
	workers         int
	decompileLimit  int
	bigFileLimit    int
	cfrHeapMB       int
	memoryLimit     int64
	totalMemory     uint64
	availableMemory uint64
}

// TuningInfo is the effective resource policy for one Engine.
type TuningInfo struct {
	Workers           int
	DecompileLimit    int
	BigFileLimit      int
	MemoryLimitMB     int64
	TotalMemoryMB     int64
	AvailableMemoryMB int64
}

func detectTuning(opts Options) systemTuning {
	total, available := systemMemory()
	t := systemTuning{
		totalMemory:     total,
		availableMemory: available,
	}
	if opts.Workers > 0 {
		t.workers = opts.Workers
	} else {
		t.workers = chooseWorkers(runtime.GOMAXPROCS(0), available)
	}
	t.decompileLimit = chooseDecompileLimit(total, available)
	t.bigFileLimit = chooseBigFileLimit(available)
	t.cfrHeapMB = chooseCFRHeap(total, available)
	t.memoryLimit = chooseMemoryLimit(total, available)
	if os.Getenv("GOMEMLIMIT") != "" {
		// The user explicitly set a Go memory limit; do not override it.
		t.memoryLimit = 0
	}
	return t
}

// chooseWorkers caps file-level parallelism by CPU count and available RAM.
// 4 GB available gets 4 workers, 2 GB gets 2, and 1 GB gets 1. Explicit
// --workers always wins.
func chooseWorkers(cpus int, available uint64) int {
	base := cpus
	if base > 8 {
		base = 8
	}
	if base < 1 {
		base = 1
	}
	if available == 0 {
		return base
	}
	usable := available * 3 / 4
	n := int(usable / workerMemoryBudget)
	if n < 1 {
		n = 1
	}
	if n > base {
		n = base
	}
	return n
}

// chooseDecompileLimit limits concurrent CFR processes. Java is a separate
// process with its own heap, so it needs a different budget than Go workers.
func chooseDecompileLimit(total, available uint64) int {
	mem := available
	if mem == 0 {
		mem = total
	}
	if mem == 0 {
		return 2
	}
	if mem < 3<<30 {
		return 1
	}
	return 2
}

// chooseBigFileLimit limits how many files above bigFileThreshold are
// processed at once. Small files can still use all workers.
func chooseBigFileLimit(available uint64) int {
	if available == 0 {
		return 1
	}
	if available < 6<<30 {
		return 1
	}
	return 2
}

// chooseMemoryLimit returns a Go soft memory limit that leaves headroom for
// the OS and for up to two CFR Java processes.
func chooseMemoryLimit(total, available uint64) int64 {
	base := total
	if base == 0 {
		base = available
	}
	if base == 0 {
		return 0
	}
	limit := int64(base * 55 / 100)
	if available > 0 {
		byAvailable := int64(available * 70 / 100)
		if byAvailable < limit {
			limit = byAvailable
		}
	}
	if limit < minimumMemoryLimit {
		limit = minimumMemoryLimit
	}
	return limit
}

// chooseCFRHeap reduces the CFR heap on low-memory machines. CFR is a
// separate JVM process; two 1 GB heaps can otherwise exhaust a 4 GB system.
func chooseCFRHeap(total, available uint64) int {
	if total > 0 && total < 6<<30 {
		return 512
	}
	if available > 0 && available < 2<<30 {
		return 512
	}
	return 1024
}

func (e *Engine) Tuning() TuningInfo {
	t := e.tuning
	return TuningInfo{
		Workers:           e.opts.Workers,
		DecompileLimit:    t.decompileLimit,
		BigFileLimit:      t.bigFileLimit,
		MemoryLimitMB:     t.memoryLimit >> 20,
		TotalMemoryMB:     int64(t.totalMemory >> 20),
		AvailableMemoryMB: int64(t.availableMemory >> 20),
	}
}

// applyTuning sets the Go memory limit once per process. The limit is a soft
// limit: it makes GC work earlier instead of waiting for an OOM kill.
func applyTuning(t systemTuning) {
	if t.memoryLimit > 0 {
		debug.SetMemoryLimit(t.memoryLimit)
	}
}

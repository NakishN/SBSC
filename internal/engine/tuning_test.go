package engine

import (
	"os"
	"testing"
)

func TestChooseWorkers(t *testing.T) {
	cases := []struct {
		name      string
		cpus      int
		available uint64
		want      int
	}{
		{"no memory info", 12, 0, 8},
		{"one GB", 12, 1 << 30, 1},
		{"two GB", 12, 2 << 30, 2},
		{"four GB", 12, 4 << 30, 4},
		{"sixteen GB", 12, 16 << 30, 8},
		{"four cpus", 4, 32 << 30, 4},
		{"one cpu", 1, 32 << 30, 1},
	}
	for _, tc := range cases {
		if got := chooseWorkers(tc.cpus, tc.available); got != tc.want {
			t.Errorf("%s: chooseWorkers(%d, %d) = %d, want %d", tc.name, tc.cpus, tc.available, got, tc.want)
		}
	}
}

func TestChooseMemoryLimit(t *testing.T) {
	if got := chooseMemoryLimit(0, 0); got != 0 {
		t.Fatalf("unknown memory must not set a limit, got %d", got)
	}
	if got := chooseMemoryLimit(16<<30, 4<<30); got < 2<<30 || got > 3<<30 {
		t.Fatalf("16GB/4GB limit = %d, want ~2.8GB", got)
	}
	if got := chooseMemoryLimit(4<<30, 1<<30); got < 512<<20 || got > 1<<30 {
		t.Fatalf("4GB/1GB limit = %d, want 512MB..1GB", got)
	}
	if got := chooseMemoryLimit(1<<30, 128<<20); got < 256<<20 {
		t.Fatalf("minimum memory limit = %d, want >= 256MB", got)
	}
}

func TestChooseDecompileLimit(t *testing.T) {
	if got := chooseDecompileLimit(0, 0); got != 2 {
		t.Fatalf("unknown memory decompile limit = %d, want 2", got)
	}
	if got := chooseDecompileLimit(4<<30, 2<<30); got != 1 {
		t.Fatalf("2GB decompile limit = %d, want 1", got)
	}
	if got := chooseDecompileLimit(16<<30, 8<<30); got != 2 {
		t.Fatalf("8GB decompile limit = %d, want 2", got)
	}
}

func TestChooseBigFileLimit(t *testing.T) {
	if got := chooseBigFileLimit(0); got != 1 {
		t.Fatalf("unknown memory big-file limit = %d, want 1", got)
	}
	if got := chooseBigFileLimit(2 << 30); got != 1 {
		t.Fatalf("2GB big-file limit = %d, want 1", got)
	}
	if got := chooseBigFileLimit(4 << 30); got != 1 {
		t.Fatalf("4GB big-file limit = %d, want 1", got)
	}
	if got := chooseBigFileLimit(8 << 30); got != 2 {
		t.Fatalf("8GB big-file limit = %d, want 2", got)
	}
	if got := chooseBigFileLimit(32 << 30); got != 2 {
		t.Fatalf("32GB big-file limit = %d, want 2", got)
	}
}

func TestChooseCFRHeap(t *testing.T) {
	if got := chooseCFRHeap(4<<30, 2<<30); got != 512 {
		t.Fatalf("4GB system CFR heap = %d, want 512", got)
	}
	if got := chooseCFRHeap(16<<30, 1<<30); got != 512 {
		t.Fatalf("1GB available CFR heap = %d, want 512", got)
	}
	if got := chooseCFRHeap(16<<30, 8<<30); got != 1024 {
		t.Fatalf("16GB system CFR heap = %d, want 1024", got)
	}
}

func TestNewAutoTunes(t *testing.T) {
	eng, err := New(Options{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	tune := eng.Tuning()
	if tune.Workers < 1 || tune.Workers > 8 {
		t.Fatalf("auto workers = %d", tune.Workers)
	}
	if eng.Options().Workers != tune.Workers {
		t.Fatalf("Options.Workers = %d, Tuning.Workers = %d", eng.Options().Workers, tune.Workers)
	}
	if tune.DecompileLimit < 1 || tune.DecompileLimit > 2 {
		t.Fatalf("decompile limit = %d", tune.DecompileLimit)
	}
	if tune.BigFileLimit < 1 || tune.BigFileLimit > 2 {
		t.Fatalf("big-file limit = %d", tune.BigFileLimit)
	}
	if eng.bigFileSem == nil || eng.decompileSem == nil {
		t.Fatal("resource semaphores were not created")
	}

	explicit, err := New(Options{OutDir: t.TempDir(), Workers: 3, CFRHeapMB: 768})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Options().Workers != 3 {
		t.Fatalf("explicit workers overwritten: %d", explicit.Options().Workers)
	}
	if explicit.decomp.HeapMB != 768 {
		t.Fatalf("explicit CFR heap overwritten: %d", explicit.decomp.HeapMB)
	}
}

func TestSystemMemory(t *testing.T) {
	total, available := systemMemory()
	if total > 0 && available > total {
		t.Fatalf("available memory (%d) exceeds total (%d)", available, total)
	}
	if os.Getenv("GOMEMLIMIT") == "" && total > 0 && available > 0 {
		eng, err := New(Options{OutDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if eng.Tuning().MemoryLimitMB <= 0 {
			t.Fatal("memory limit was not set despite available memory info")
		}
	}
}

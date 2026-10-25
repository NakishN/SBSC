//go:build windows

package ui

import (
	"testing"

	"github.com/lxn/walk"

	"sbsc/internal/engine"
)

func TestResultsModelSort(t *testing.T) {
	m := &resultsModel{}
	m.Add(&engine.ScanResult{Name: "beta.jar", Verdict: "ЧИТ-КЛИЕНТ", Risk: 80})
	m.Add(&engine.ScanResult{Name: "alpha.jar", Verdict: "ЧИСТО", Risk: 0})
	m.Add(&engine.ScanResult{Name: "gamma.jar", Verdict: "ПОДОЗРИТЕЛЬНЫЙ", Risk: 35})

	if err := m.Sort(3, walk.SortAscending); err != nil {
		t.Fatal(err)
	}
	if got := m.all[0].Risk; got != 0 {
		t.Fatalf("ascending risk: first=%d, want 0", got)
	}
	if m.Items()[0].Name != "alpha.jar" {
		t.Fatalf("visible order not rebuilt: %v", m.Items())
	}

	if err := m.Sort(3, walk.SortDescending); err != nil {
		t.Fatal(err)
	}
	if got := m.all[0].Risk; got != 80 {
		t.Fatalf("descending risk: first=%d, want 80", got)
	}

	if err := m.Sort(1, walk.SortAscending); err != nil {
		t.Fatal(err)
	}
	if got := m.all[0].Name; got != "alpha.jar" {
		t.Fatalf("name sort: first=%q", got)
	}
	if m.ColumnSortable(0) || !m.ColumnSortable(1) {
		t.Fatal("unexpected sortable columns")
	}
}

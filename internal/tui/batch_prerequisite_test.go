package tui

import (
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules/pwntools"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestOrderBatchPlacesRustHoundBeforeWritableAnalysis(t *testing.T) {
	writable := runner.BatchItem{Module: pwntools.ADWritableObjects{}}
	collector := runner.BatchItem{Module: rusthound.Module{}}
	ordered := orderBatch([]runner.BatchItem{writable, collector})
	if len(ordered) != 2 {
		t.Fatalf("ordered batch length=%d, want 2", len(ordered))
	}
	if ordered[0].Module.ID() != "rusthound-ce" || ordered[1].Module.ID() != "ad-writable-objects" {
		t.Fatalf("ordered IDs=%s,%s, want rusthound-ce,ad-writable-objects", ordered[0].Module.ID(), ordered[1].Module.ID())
	}
}

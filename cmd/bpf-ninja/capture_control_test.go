package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunLossDoesNotAbort(t *testing.T) {
	for _, loss := range []bool{false, true} {
		c := &captureControl{}
		c.observeRunLoss(loss, nil)
		c.observeRunLoss(false, nil)
		if c.runIncomplete.Load() != loss {
			t.Fatal("loss must remain sticky")
		}
	}
	c := &captureControl{}
	first := fmt.Errorf("sample failed")
	c.observeRunLoss(false, first)
	c.observeRunLoss(false, fmt.Errorf("later error"))
	if !c.runIncomplete.Load() || !errors.Is(c.runDiagnosticError(), first) {
		t.Fatal("first diagnostic error lost")
	}
	if got := c.tagCompletion(7, "out.7.pcapng"); !strings.Contains(got, "run tracking incomplete") {
		t.Fatal(got)
	}
	if got := (&captureControl{}).tagCompletion(7, "out.7.pcapng"); strings.Contains(got, "incomplete") {
		t.Fatal(got)
	}
}

package program

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestStaticCtxRefusedTargetSkipped(t *testing.T) {
	var results targetAttachResults
	results.attached()
	results.refused(attach.Target{ProgID: 42, FuncName: "unsafe"}, attach.TargetStaticCtxRefused, errors.New("R1 is not the context"))

	if err := results.err(); err != nil {
		t.Fatalf("one attached target must keep the capture alive: %v", err)
	}
	if len(results.diagnostics) != 1 || results.diagnostics[0].Reason != attach.TargetStaticCtxRefused {
		t.Fatalf("diagnostics = %+v", results.diagnostics)
	}
}

func TestStaticCtxRefusedOnlyTargetFails(t *testing.T) {
	var results targetAttachResults
	results.refused(attach.Target{ProgID: 42, FuncName: "unsafe"}, attach.TargetStaticCtxRefused, errors.New("R1 is not the context"))

	err := results.err()
	if err == nil || !strings.Contains(err.Error(), "no target attached") || !strings.Contains(err.Error(), "R1 is not the context") {
		t.Fatalf("err = %v", err)
	}
}

func TestObserverLoadRefusedTargetSkipped(t *testing.T) {
	var results targetAttachResults
	results.refused(attach.Target{ProgID: 42, FuncName: "rejected"}, attach.TargetObserverLoadFailed, errors.New("verifier rejected observer"))
	results.attached()

	if err := results.err(); err != nil {
		t.Fatal(err)
	}
	if got := results.diagnostics[0].Detail; got != "verifier rejected observer" {
		t.Fatalf("detail = %q", got)
	}
}

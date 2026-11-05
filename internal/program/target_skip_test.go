package program

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestStaticCtxRefusedTargetSkipped(t *testing.T) {
	var results targetAttachResults
	results.didAttach(0)
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
	results.didAttach(1)

	if err := results.err(); err != nil {
		t.Fatal(err)
	}
	if got := results.diagnostics[0].Detail; got != "verifier rejected observer" {
		t.Fatalf("detail = %q", got)
	}
	if len(results.attached) != 1 || results.attached[0] != 1 {
		t.Fatalf("attached = %v", results.attached)
	}
}

type testCloser struct {
	name   string
	closed *[]string
}

func (c *testCloser) Close() error {
	*c.closed = append(*c.closed, c.name)
	return nil
}

func TestCloseTargetResourcesLeavesPriorTargets(t *testing.T) {
	var closed []string
	resources := []*testCloser{{name: "prior", closed: &closed}, {name: "stage-1", closed: &closed}, {name: "stage-2", closed: &closed}}
	resources = closeTargetResources(resources, 1)
	if len(resources) != 1 || resources[0].name != "prior" {
		t.Fatalf("resources = %+v", resources)
	}
	if got := strings.Join(closed, ","); got != "stage-2,stage-1" {
		t.Fatalf("close order = %q", got)
	}
}

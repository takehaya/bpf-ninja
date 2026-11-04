//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
	"golang.org/x/sys/unix"
)

func TestCheckLoadRejectsTamperedStream(t *testing.T) {
	data, err := os.ReadFile("../../cmd/inject-check/testdata/pairs/fixture-1-static-any.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair injectcheck.Pair
	if err := json.Unmarshal(data, &pair); err != nil {
		t.Fatal(err)
	}
	encode := func(insns asm.Instructions) []byte {
		t.Helper()
		var buf bytes.Buffer
		if err := insns.Marshal(&buf, wire); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	original, err := asm.AppendInstructions(nil, bytes.NewReader(encode(asm.Instructions(pair.Original))), wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	stream := encode(asm.Instructions(pair.Transformed))
	verdict, err := checkLoad(original, stream, pair.Certificate, pair.Premises)
	if err != nil || !verdict.Accepted {
		t.Fatalf("baseline: %+v: %v", verdict, err)
	}

	decoded, err := asm.AppendInstructions(nil, bytes.NewReader(stream), wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	decoded[pair.Certificate.Hooks[0].Start] = asm.FnKtimeGetNs.Call()
	verdict, err = checkLoad(original, encode(decoded), pair.Certificate, pair.Premises)
	if err == nil || verdict.Accepted {
		t.Fatalf("tampered load was not rejected: %+v: %v", verdict, err)
	}
	for _, failClosed := range []bool{false, true} {
		retried := false
		ret, policyErr := retryOriginalOrRefuse(failClosed, func() (int64, error) {
			retried = true
			return 42, nil
		})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		if failClosed && (retried || ret != -int64(unix.EPERM)) {
			t.Fatalf("fail-closed retried=%v ret=%d", retried, ret)
		}
		if !failClosed && (!retried || ret != 42) {
			t.Fatalf("default retried=%v ret=%d", retried, ret)
		}
	}
}

func TestCallxCheckPolicy(t *testing.T) {
	callx := asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call).SetSource(asm.RegSource), Src: asm.R3}
	_, notApplicable := inject.BuildLookupTargets(asm.Instructions{callx}, nil)
	if !errors.Is(notApplicable, inject.ErrCheckerNotApplicable) {
		t.Fatalf("callx was not classified: %v", notApplicable)
	}
	check, err := loadCheckPolicy(notApplicable, false)
	if check || err != nil {
		t.Fatalf("default did not proceed unchecked: check=%v err=%v", check, err)
	}
	check, err = loadCheckPolicy(notApplicable, true)
	if check || !errors.Is(err, inject.ErrCheckerNotApplicable) {
		t.Fatalf("fail-closed did not refuse: check=%v err=%v", check, err)
	}
}

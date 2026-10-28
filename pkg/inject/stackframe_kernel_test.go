package inject

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfStackBoundShallowLeaf(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, dispatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("dispatch=%t", dispatch), func(t *testing.T) {
			plain := loadOrSkip(t, stackBoundFixture(8))
			t.Cleanup(plain.Close)
			work := stackBoundFixture(8)
			if _, err := transformLookup(work, stackBoundRequest(dispatch)); err != nil {
				t.Fatal(err)
			}
			injected := loadOrSkip(t, work)
			t.Cleanup(injected.Close)
			packet := make([]byte, 64)
			pr, po, err := plain.Programs["p"].Test(packet)
			if err != nil {
				t.Fatal(err)
			}
			ir, io, err := injected.Programs["p"].Test(packet)
			if err != nil || pr != ir || !bytes.Equal(po, io) {
				t.Fatalf("plain=%d/%x injected=%d/%x: %v", pr, po, ir, io, err)
			}
		})
	}
}

func TestBpfStackBoundDeepLeafRefused(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	// Plain rounds to 256+256. An instrumented 280/288-byte entry
	// plus the 248-byte leaf exceeds 512 under both frame roundings.
	plain := loadOrSkip(t, stackBoundFixture(248))
	t.Cleanup(plain.Close)
	for _, dispatch := range []bool{false, true} {
		req := stackBoundRequest(dispatch)
		req.Stack.LowestOffset = -248
		if _, err := transformLookup(stackBoundFixture(248), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "512-byte combined limit") {
			t.Fatalf("dispatch=%t: want combined-stack refusal, got %v", dispatch, err)
		}
	}
	// Independently ask the kernel about that actual deeper chain, without
	// bypassing the transform's refusal to generate an instrumented program.
	tooDeep := stackBoundFixture(248)
	tooDeep.Programs["p"].Instructions[2].Offset = -280
	c, err := ebpf.NewCollection(tooDeep)
	if err == nil {
		c.Close()
		t.Fatal("kernel accepted a chain exceeding 512 bytes")
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) || !strings.Contains(fmt.Sprintf("%+v", ve), "combined stack size") {
		t.Fatalf("want kernel combined-stack rejection, got %+v", err)
	}
}

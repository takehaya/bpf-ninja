package dsltest

import (
	"encoding/hex"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/cgroupskb"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/netfilter"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
	"github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
)

// specHostCaps mirrors Kunai/Host.lean HostKind.host.
var specHostCaps = map[string]func() codegen.Capabilities{
	"xdp_entry":        func() codegen.Capabilities { return codegen.Capabilities{} },
	"xdp_exit":         xdp.FexitCapabilities,
	"tc_entry":         tc.EntryCapabilities,
	"tc_exit":          tc.FexitCapabilities,
	"cgroup_skb_entry": cgroupskb.EntryCapabilities,
	"cgroup_skb_exit":  cgroupskb.FexitCapabilities,
	"netfilter_entry":  netfilter.EntryCapabilities,
	"netfilter_exit":   netfilter.FexitCapabilities,
}

// TestSpecVectors checks the Go implementation against the Lean semantics.
// Without root only parsing and the illTyped/notImplemented compile
// expectations run; with root, every vector whose compile is expected to
// succeed is also matched against the real BPF program, compiled for the
// vector's host and, on an exit host, with the vector's action as the
// traced program's return value. A vector with goStatus "mismatch" is a documented
// divergence (see spec/lean/DECISIONS.md): it is logged, not asserted.
func TestSpecVectors(t *testing.T) { runSpecVectors(t, loadSpecVectors(t)) }

// TestSpecVectorsGenerated runs the mutated vectors (truncations and byte
// flips of the golden packets); their verdicts come from the Lean
// evaluator at generation time.
func TestSpecVectorsGenerated(t *testing.T) {
	runSpecVectors(t, loadSpecVectorsFrom(t, specVectorsGenPath))
}

func runSpecVectors(t *testing.T, vectors []specVector) {
	root := os.Getuid() == 0
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			hostCaps, ok := specHostCaps[v.Host]
			if !ok {
				t.Fatalf("unknown host %q", v.Host)
			}
			// Lean models actions as 32-bit values (TC_ACT_UNSPEC is 2^32-1).
			if v.Action < 0 || v.Action > math.MaxUint32 {
				t.Fatalf("action %d is not a 32-bit value", v.Action)
			}
			caps := func() codegen.Capabilities {
				return HostCaps(Host{Caps: hostCaps(), Action: int32(uint32(v.Action))})
			}
			if v.GoStatus == "mismatch" {
				_, err := kunai.Compile(v.Expr, caps())
				t.Logf("documented divergence (not asserted): %s; compile err=%v", v.Note, err)
				return
			}
			if _, err := parser.Parse(v.Expr, "", nil); err != nil && v.Expected.Kind != "illTyped" {
				t.Fatalf("parse %q: %v", v.Expr, err)
			}
			out, err := kunai.Compile(v.Expr, caps())
			switch {
			case v.GoStatus == "notImplemented":
				if !errors.Is(err, codegen.ErrNotImplemented) {
					t.Fatalf("Compile(%q) = %v; want ErrNotImplemented (%s)", v.Expr, err, v.Note)
				}
				return
			case v.Expected.Kind == "illTyped":
				// The resolver must reject it; an ErrNotImplemented is an
				// implementation limit and belongs under goStatus notImplemented.
				if err == nil || errors.Is(err, codegen.ErrNotImplemented) {
					t.Fatalf("Compile(%q) = %v; Lean: illTyped %q", v.Expr, err, v.Expected.Reason)
				}
				return
			case err != nil:
				t.Fatalf("Compile(%q): %v", v.Expr, err)
			}
			if !root {
				return
			}
			pkt, err := hex.DecodeString(v.Packet)
			if err != nil {
				t.Fatalf("packet hex: %v", err)
			}
			want := v.Expected.Kind == "accept"
			if got := NewFromOutput(t, v.Expr, out).Match(t, pkt); got != want {
				t.Fatalf("%q on %d-byte packet: got match=%v, Lean says %s. %s", v.Expr, len(pkt), got, v.Expected.Kind, v.Note)
			}
		})
	}
}

package program

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

func TestBpfExtensionCapture(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, tt := range []struct {
		name, ctx, section string
		typ                ebpf.ProgramType
		pass               int
	}{
		{"xdp", "xdp_md", "xdp", ebpf.XDP, 2},
		{"tc", "__sk_buff", "tc", ebpf.SchedCLS, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := fmt.Sprintf(`
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
__attribute__((noinline))
int slot(struct %s *ctx, int orig_ret) {
    return ctx->data == ctx->data_end ? 1 : orig_ret;
}
__attribute__((noinline))
int unused_slot(struct %s *ctx) { return ctx->data == ctx->data_end; }
SEC("%s")
int dispatcher(struct %s *ctx) {
    int ret = unused_slot(ctx) ? 1 : %d;
    return slot(ctx, ret);
}
char _license[] SEC("license") = "GPL";
`, tt.ctx, tt.ctx, tt.section, tt.ctx, tt.pass)
			dispatcher := loadXDPByName(t, source, "dispatcher")
			extSource := fmt.Sprintf(`
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("freplace/slot")
int replacement(struct %s *ctx, int orig_ret) {
    return ctx->data == ctx->data_end ? 1 : orig_ret;
}
char _license[] SEC("license") = "GPL";
`, tt.ctx)
			spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, extSource))
			if err != nil {
				t.Fatal(err)
			}
			ps := spec.Programs["replacement"]
			ps.AttachTarget = dispatcher
			ext, err := ebpf.NewProgram(ps)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ext.Close() }()
			pi, err := ext.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := pi.ID()
			if _, err := attach.FindBPFProgramByID(uint32(id)); err == nil || !strings.Contains(err.Error(), "unattached") {
				t.Fatalf("unattached EXT: %v", err)
			}
			lnk, err := link.AttachFreplace(dispatcher, "slot", ext)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lnk.Close() }()
			info, err := attach.FindBPFProgramByID(uint32(id))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = info.Program.Close() }()
			if info.Type != ebpf.Extension || info.HookType != tt.typ {
				t.Fatalf("types: %s / %s", info.Type, info.HookType)
			}
			if err := attach.CheckReplacedFunc(dispatcher, "slot"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("-p %d", id)) {
				t.Fatalf("stub guard: %v", err)
			}
			di, err := dispatcher.Info()
			if err != nil {
				t.Fatal(err)
			}
			did, _ := di.ID()
			children, err := attach.WalkReachablePrograms(dispatcher, uint32(did))
			if err != nil || len(children) != 1 || children[0].ProgID != uint32(id) || children[0].Via != "freplace" {
				t.Fatalf("children: %v, %v", children, err)
			}
			targets, err := attach.ResolveTargets([]*attach.ProgInfo{info}, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			// Exercise the public loader: the hard guard cannot be overridden.
			for _, allow := range []bool{false, true} {
				for _, fn := range []string{"slot", "unused_slot", "dispatcher"} {
					target := attach.Target{Program: dispatcher, ProgID: uint32(did), Type: tt.typ, HookType: tt.typ, FuncName: fn, AllowDispatcherSlot: allow}
					p, err := LoadMultiPoint([]attach.Target{target}, []Stage{{}}, nil, true, nil, EmitBoth)
					wantError := fn == "slot" || (fn == "unused_slot" && !allow)
					if p != nil {
						_ = p.Close()
					}
					if wantError {
						hint := "--allow-dispatcher-slot"
						if fn == "slot" {
							hint = fmt.Sprintf("-p %d", id)
						}
						if err == nil || !strings.Contains(err.Error(), hint) {
							t.Fatalf("guard %s override=%v: %v", fn, allow, err)
						}
					} else if err != nil {
						t.Fatalf("attach %s override=%v: %v", fn, allow, err)
					}
				}
			}
			packet := dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})
			for _, tc := range []struct {
				name   string
				stages []Stage
				reject bool
			}{
				{"entry", []Stage{{Expr: "eth/ipv4"}}, false},
				{"exit", []Stage{{Expr: "eth/ipv4", IsFexit: true}}, false},
				{"gated", []Stage{{Expr: "eth/ipv4"}, {Expr: "eth/ipv4", IsFexit: true}}, false},
				{"argument-miss", []Stage{{Expr: "eth/ipv4"}}, true},
				{"entry-miss", []Stage{{Expr: "eth/ipv6"}, {Expr: "eth/ipv4", IsFexit: true}}, false},
				{"exit-miss", []Stage{{Expr: "eth/ipv4"}, {Expr: "eth/ipv6", IsFexit: true}}, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					origRet := tt.pass
					if tc.reject {
						origRet++
					}
					args, err := filter.ParseAndValidateFilters([]string{fmt.Sprintf("orig_ret=%d", origRet)}, targets[0].Params)
					if err != nil {
						t.Fatal(err)
					}
					probe, err := LoadMultiPoint(targets, tc.stages, []filter.TargetFilters{{Args: args}}, true, nil, EmitBoth)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = probe.Close() }()
					ret, err := dispatcher.Run(&ebpf.RunOptions{Data: packet})
					if err != nil || ret != uint32(tt.pass) {
						t.Fatalf("run: ret=%d err=%v", ret, err)
					}
					if err := probe.Quiesce(); err != nil {
						t.Fatal(err)
					}
					var records []capture.Packet
					for _, m := range probe.InnerMaps {
						r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
						if err != nil {
							t.Fatal(err)
						}
						r.ReadBatch(func(raw []byte) {
							p, err := capture.ParseRawSample(raw)
							if err != nil {
								t.Error(err)
								return
							}
							p.Data = append([]byte(nil), p.Data...)
							records = append(records, p)
						})
						_ = r.Close()
					}
					want := len(tc.stages)
					if strings.Contains(tc.name, "miss") {
						want = 0
					}
					if len(records) != want {
						t.Fatalf("records=%d want=%d", len(records), want)
					}
					for i, p := range records {
						action := uint32(tt.pass)
						if len(tc.stages) == 1 && !tc.stages[0].IsFexit {
							action = 0
						}
						mode := uint8(0)
						if tc.stages[i].IsFexit {
							mode = 1
						}
						if !bytes.Equal(p.Data, packet) || int(p.CapLen) != len(packet) || p.Action != action || p.Mode != mode {
							t.Fatalf("record %d: %+v, want bytes=%x action=%d mode=%d", i, p, packet, action, mode)
						}
					}
					if want == 2 && (records[0].PacketID == 0 || records[0].PacketID != records[1].PacketID) {
						t.Fatal("gated records are not paired")
					}
				})
			}
		})
	}
}

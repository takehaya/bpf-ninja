package inject

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
	"golang.org/x/sys/unix"
)

// loadWithDepth loads spec, closes it at cleanup and returns the verifier's
// stack depth of its first function.
func loadWithDepth(t *testing.T, spec *ebpf.CollectionSpec) (*ebpf.Collection, int) {
	t.Helper()
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 64 << 10},
	})
	if err != nil {
		t.Fatalf("load: %+v", err)
	}
	t.Cleanup(coll.Close)
	depths, err := ParseStackDepths(coll.Programs["p"].VerifierLog)
	if err != nil {
		t.Fatal(err)
	}
	return coll, depths[0]
}

// textDepth is the deepest direct stack access of function p in spec.
func textDepth(t *testing.T, spec *ebpf.CollectionSpec) int {
	t.Helper()
	insns := spec.Programs["p"].Instructions
	ranges, err := instructionFunctions(insns)
	if err != nil {
		t.Fatal(err)
	}
	depth, _ := stackFrameDepthExact(insns[ranges[0].start:ranges[0].end], 0)
	return depth
}

// E3: a hook at bpf_get_smp_processor_id between its fastcall spill and fill
// loads and sees the CPU the program stores, the filled R1 is unchanged, and
// the frame floor taken from the trial load covers the spill even where the
// kernel removed it. The hooked p's verifier depth is its text depth: the
// hook breaks the pattern, so nothing is removed after rewriting.
func TestBpfCallHookRowSmpProcessorID(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain, plainDepth := loadWithDepth(t, fastcallFixture())
	report, err := FrameFloors([]int{plainDepth}, []string{"p"}, fastcallFixture().Programs["p"].Instructions, KernelInfo{})
	if err != nil {
		t.Fatal(err)
	}
	spec := fastcallFixture()
	req := callReq("bpf_get_smp_processor_id")
	req.Stack = StackAudit{Frames: report.Frames(), Source: "verifier"}
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	coll, hookedDepth := loadWithDepth(t, spec)
	obs := attachArgObserver(t, plan.hooks[0].Name, coll.Programs["p"], false, false)
	text := textDepth(t, spec)
	t.Logf("plain verifier depth %d, tool floor %d, hooked verifier depth %d, hooked text depth %d", plainDepth, -report.Functions[0].Floor, hookedDepth, text)
	if -int(report.Functions[0].Floor) < 8 {
		t.Fatalf("tool floor %d does not cover the spill at fp-8", report.Functions[0].Floor)
	}
	if hookedDepth != text {
		t.Fatalf("hooked verifier depth %d, text depth %d", hookedDepth, text)
	}
	for run := 1; run <= 3; run++ {
		pret, pout := runCallFixture(t, plain, make([]byte, 64), nil)
		ret, out := runCallFixture(t, coll, make([]byte, 64), nil)
		if pret != 2 || ret != 2 || pout[1] != 7 || out[1] != 7 {
			t.Fatalf("run %d: actions %d %d, filled R1 %d %d", run, pret, ret, pout[1], out[1])
		}
		got := lastCall(t, obs, run)
		if got[0] != uint64(plan.hooks[0].Sites[0].SitePC) || got[1] != out[0] {
			t.Fatalf("run %d: hook site %d ret %d, want %d and %d", run, got[0], got[1], plan.hooks[0].Sites[0].SitePC, out[0])
		}
	}
}

// testCallHookRowScalars hooks each of names in ctxScalarFixture(typ, fns...)
// and checks over three runs that each hook sees, at its site, the result
// the program stores, and that the action is unchanged.
func testCallHookRowScalars(t *testing.T, typ ebpf.ProgramType, names []string, fns ...asm.BuiltinFunc) [4]uint64 {
	testutil.SkipIfNotRoot(t)
	_, pass, _ := callVerdicts(typ)
	coll, plan, obs := callHooked(t, ctxScalarFixture(typ, fns...), callReq(names...))
	var out [4]uint64
	for run := 1; run <= 3; run++ {
		var ret uint32
		ret, out = runCallFixture(t, coll, make([]byte, 64), nil)
		if int32(ret) != pass {
			t.Fatalf("run %d: action %d, want %d", run, ret, pass)
		}
		for _, h := range plan.hooks {
			slot := slices.Index(names, h.Call)
			got := lastCall(t, obs[h.Call], run)
			if got[0] != uint64(h.Sites[0].SitePC) || got[1] != out[slot] {
				t.Fatalf("run %d %s: site %d ret %#x, want %d and %#x", run, h.Call, got[0], got[1], h.Sites[0].SitePC, out[slot])
			}
		}
	}
	return out
}

func TestBpfCallHookRowHashCookieTC(t *testing.T) {
	out := testCallHookRowScalars(t, ebpf.SchedCLS, []string{"bpf_get_hash_recalc", "bpf_get_socket_cookie"}, asm.FnGetHashRecalc, asm.FnGetSocketCookie)
	t.Logf("hash %#x cookie %#x", out[0], out[1])
}

func TestBpfCallHookRowXdpBuffLen(t *testing.T) {
	if out := testCallHookRowScalars(t, ebpf.XDP, []string{"bpf_xdp_get_buff_len"}, asm.FnXdpGetBuffLen); out[0] != 64 {
		t.Fatalf("bpf_xdp_get_buff_len %d, want 64", out[0])
	}
}

// testCallHookRowLoadBytes hooks loadBytesFixture(typ): on a 64-byte packet
// the hook sees code 0 and the copied bytes through arg, on a 32-byte one
// -short and the buffer the callee left (zero), and the action is unchanged.
func testCallHookRowLoadBytes(t *testing.T, typ ebpf.ProgramType, name string, short unix.Errno) {
	testutil.SkipIfNotRoot(t)
	coll, plan, obs := callHooked(t, loadBytesFixture(typ), callReq(name))
	h := plan.hooks[0]
	if h.ArgReg != 3 || h.ArgType != "" || h.ArgSize != loadBytesLen || h.RetPtr {
		t.Fatalf("hook %+v", h)
	}
	_, pass, drop := callVerdicts(typ)
	packet := make([]byte, 64)
	copy(packet[loadBytesAt:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	want := binary.LittleEndian.Uint64(packet[loadBytesAt:])
	for run, c := range []struct {
		data        []byte
		action      int32
		code, data8 uint64
	}{{packet, pass, 0, want}, {packet[:32], drop, uint64(-int64(short)), 0}} {
		ret, out := runCallFixture(t, coll, c.data, nil)
		got := lastCall(t, obs[name], run+1)
		if int32(ret) != c.action || out[0] != c.code || out[1] != c.data8 {
			t.Fatalf("%d-byte packet: action %d, out %#x", len(c.data), ret, out)
		}
		if got[0] != uint64(h.Sites[0].SitePC) || got[1] != c.data8 || got[2] != out[0] {
			t.Fatalf("%d-byte packet: hook site %d arg %#x ret %#x, want %d %#x %#x", len(c.data), got[0], got[1], got[2], h.Sites[0].SitePC, c.data8, c.code)
		}
	}
}

func TestBpfCallHookRowLoadBytesXDP(t *testing.T) {
	testCallHookRowLoadBytes(t, ebpf.XDP, "bpf_xdp_load_bytes", unix.EINVAL)
}

func TestBpfCallHookRowLoadBytesTC(t *testing.T) {
	testCallHookRowLoadBytes(t, ebpf.SchedCLS, "bpf_skb_load_bytes", unix.EFAULT)
}

// loadBytesMapFixture copies packet bytes into an array-map value instead of
// the function's stack, making the call hook untyped.
func loadBytesMapFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("buf"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "lbm_drop"), asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, loadBytesAt), asm.Mov.Reg(asm.R3, asm.R7), asm.Mov.Imm(asm.R4, loadBytesLen),
		asm.FnXdpLoadBytes.Call(), asm.Mov.Reg(asm.R8, asm.R0),
	}
	insns = append(insns, outStore(0, asm.R8)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R7, 0, asm.DWord), asm.StoreMem(asm.R1, 8, asm.R2, asm.DWord),
		asm.JEq.Imm(asm.R8, 0, "lbm_pass"),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("lbm_drop"), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("lbm_pass"), asm.Return())
	spec := callFixtureSpec(ebpf.XDP, insns)
	spec.Maps["buf"] = &ebpf.MapSpec{Name: "buf", Type: ebpf.Array, KeySize: 4, ValueSize: loadBytesLen, MaxEntries: 1}
	return spec
}

func testCallHookRowLoadBytesMap(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	plain := loadCallFixture(t, loadBytesMapFixture())
	req := callReq("bpf_xdp_load_bytes")
	req.StaticUntrusted = static
	coll, plan, obs := callHooked(t, loadBytesMapFixture(), req)
	h := plan.hooks[0]
	if h.ArgReg != 3 || h.ArgType != "" || h.ArgSize != loadBytesLen || h.RetPtr || h.Static != static || h.Untrusted == static {
		t.Fatalf("hook %+v", h)
	}
	packet := make([]byte, 64)
	copy(packet[loadBytesAt:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	want := binary.LittleEndian.Uint64(packet[loadBytesAt:])
	pret, pout := runCallFixture(t, plain, packet, nil)
	ret, out := runCallFixture(t, coll, packet, nil)
	if ret != 2 || ret != pret || out != pout || out[0] != 0 || out[1] != want {
		t.Fatalf("hooked %d %#x, plain %d %#x", ret, out, pret, pout)
	}
	if got := lastCall(t, obs["bpf_xdp_load_bytes"], 1); got[0] != uint64(h.Sites[0].SitePC) || got[1] != want || got[2] != 0 {
		t.Fatalf("hook saw site %d arg %#x ret %#x, want %d %#x 0", got[0], got[1], got[2], h.Sites[0].SitePC, want)
	}
}

func TestBpfCallHookRowLoadBytesMap(t *testing.T) { testCallHookRowLoadBytesMap(t, true) }

// The global memory hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallHookRowLoadBytesMapUntrusted(t *testing.T) {
	testCallHookRowLoadBytesMap(t, false)
}

// skFixture is skLookupFixture(typ, dport) calling fn in place of
// bpf_sk_lookup_tcp, and with release false the bpf_sk_release replaced by
// r1 = 0.
func skFixture(typ ebpf.ProgramType, fn asm.BuiltinFunc, dport uint16, release bool) *ebpf.CollectionSpec {
	spec := skLookupFixture(typ, dport)
	insns := spec.Programs["p"].Instructions
	for i := range insns {
		switch {
		case insns[i].IsBuiltinCall() && insns[i].Constant == int64(asm.FnSkLookupTcp):
			insns[i] = fn.Call()
		case !release && insns[i].IsBuiltinCall() && insns[i].Constant == int64(asm.FnSkRelease):
			insns[i] = asm.Mov.Imm(asm.R1, 0)
		}
	}
	return spec
}

var skRows = []struct {
	name    string
	fn      asm.BuiltinFunc
	network string
}{
	{"bpf_sk_lookup_tcp", asm.FnSkLookupTcp, "tcp4"},
	{"bpf_sk_lookup_udp", asm.FnSkLookupUdp, "udp4"},
	{"bpf_skc_lookup_tcp", asm.FnSkcLookupTcp, "tcp4"},
}

// testCallHookRowSk hooks each socket lookup on a socket bound to
// 127.0.0.1: the hook sees the tuple's addresses through arg and a non-NULL
// ret while the socket exists, NULL once it is closed, and the actions match
// the plain program's.
func testCallHookRowSk(t *testing.T, typ ebpf.ProgramType, static bool) {
	testutil.SkipIfNotRoot(t)
	_, pass, drop := callVerdicts(typ)
	addrs := binary.LittleEndian.Uint64([]byte{127, 0, 0, 1, 127, 0, 0, 1})
	for _, r := range skRows {
		t.Run(r.name, func(t *testing.T) {
			var port uint16
			var closer interface{ Close() error }
			if r.network == "udp4" {
				c, err := net.ListenPacket(r.network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				closer, port = c, uint16(c.LocalAddr().(*net.UDPAddr).Port)
			} else {
				l, err := net.Listen(r.network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				closer, port = l, uint16(l.Addr().(*net.TCPAddr).Port)
			}
			defer func() { _ = closer.Close() }()
			req := callReq(r.name)
			req.StaticUntrusted = static
			plain := loadCallFixture(t, skFixture(typ, r.fn, port, true))
			coll, plan, obs := callHooked(t, skFixture(typ, r.fn, port, true), req)
			h := plan.hooks[0]
			if !h.RetPtr || h.ArgReg != 2 || h.ArgSize != 12 || h.Static != static || h.Untrusted == static {
				t.Fatalf("hook %+v", h)
			}
			for run, action := range []int32{pass, drop} {
				if run == 1 {
					if err := closer.Close(); err != nil {
						t.Fatal(err)
					}
				}
				pret, _ := runCallFixture(t, plain, make([]byte, 64), nil)
				ret, _ := runCallFixture(t, coll, make([]byte, 64), nil)
				got := lastCall(t, obs[r.name], run+1)
				if int32(ret) != action || pret != ret {
					t.Fatalf("run %d: hooked %d, plain %d, want %d", run, ret, pret, action)
				}
				if got[0] != uint64(h.Sites[0].SitePC) || got[1] != addrs || (got[2] != 0) != (action == pass) {
					t.Fatalf("run %d: hook site %d arg %#x ret %#x", run, got[0], got[1], got[2])
				}
			}
		})
	}
}

func TestBpfCallHookRowSkXDP(t *testing.T) { testCallHookRowSk(t, ebpf.XDP, true) }
func TestBpfCallHookRowSkTC(t *testing.T)  { testCallHookRowSk(t, ebpf.SchedCLS, true) }

// The global pointer-result hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallHookRowSkUntrusted(t *testing.T) { testCallHookRowSk(t, ebpf.XDP, false) }

// Without the release each hooked socket lookup is rejected as the plain
// program is: the hook does not hide the acquired reference.
func TestBpfCallHookRowSkNoRelease(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, r := range skRows {
		if coll, err := ebpf.NewCollection(skFixture(ebpf.XDP, r.fn, 1, false)); err == nil {
			coll.Close()
			t.Fatalf("%s: plain program without the release loaded", r.name)
		}
		req := callReq(r.name)
		req.StaticUntrusted = true
		work := skFixture(ebpf.XDP, r.fn, 1, false)
		if _, err := transformLookup(work, req); err != nil {
			t.Fatal(err)
		}
		coll, err := ebpf.NewCollection(work)
		if err == nil {
			coll.Close()
			t.Fatalf("%s: hooked program without the release loaded", r.name)
		}
		if log := fmt.Sprintf("%+v", err); !strings.Contains(log, "Unreleased reference") && !strings.Contains(log, "reference leak") {
			t.Fatalf("%s: hooked program rejected for another reason: %+v", r.name, err)
		}
	}
}

// The hook after bpf_probe_read_kernel sees code 0 and the copied bytes
// through arg, and after a failed read (address 0) the error and the zeroed
// buffer, as the plain program stores them.
func TestBpfCallHookRowProbeReadKernel(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, c := range []struct {
		fail  bool
		data8 uint64
	}{{false, 0x0807060504030201}, {true, 0}} {
		plain := loadCallFixture(t, probeReadFixture(c.fail))
		coll, plan, obs := callHooked(t, probeReadFixture(c.fail), callReq("bpf_probe_read_kernel"))
		h := plan.hooks[0]
		if h.ArgReg != 1 || h.ArgType != "" || h.ArgSize != 8 || h.RetPtr || h.Untrusted || h.Static {
			t.Fatalf("hook %+v", h)
		}
		pret, pout := runCallFixture(t, plain, make([]byte, 64), nil)
		ret, out := runCallFixture(t, coll, make([]byte, 64), nil)
		if ret != 2 || pret != 2 || out != pout || (out[0] != 0) != c.fail || out[1] != c.data8 {
			t.Fatalf("fail=%v: hooked %d %#x, plain %d %#x", c.fail, ret, out, pret, pout)
		}
		if got := lastCall(t, obs["bpf_probe_read_kernel"], 1); got[0] != uint64(h.Sites[0].SitePC) || got[1] != c.data8 || got[2] != out[0] {
			t.Fatalf("fail=%v: hook site %d arg %#x ret %#x", c.fail, got[0], got[1], got[2])
		}
	}
}

// loadBytesTwoSizesFixture is loadBytesFixture (XDP) with a second
// bpf_xdp_load_bytes of 4 bytes at 40 into fp-16: the codes go to out slots 0
// and 1, the buffers to 2 and 3, and it passes when both succeed, else drops.
func loadBytesTwoSizesFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, loadBytesAt),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.Mov.Imm(asm.R4, loadBytesLen),
		asm.FnXdpLoadBytes.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, 40),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), asm.Mov.Imm(asm.R4, 4),
		asm.FnXdpLoadBytes.Call(),
		asm.Mov.Reg(asm.R8, asm.R0),
	}
	insns = append(insns, outStore(0, asm.R7)...)
	insns = append(insns, asm.StoreMem(asm.R1, 8, asm.R8, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R1, 16, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord), asm.StoreMem(asm.R1, 24, asm.R2, asm.DWord),
		asm.Or.Reg(asm.R7, asm.R8),
		asm.JEq.Imm(asm.R7, 0, "lb2_pass"),
		asm.Mov.Imm(asm.R0, 1), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("lb2_pass"), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

// A callee with two argument sizes gets the result-only hook at both sites:
// the load-time checker accepts the rewrite, the program acts and stores as
// the unmodified one, and the hook sees each site's result, on a packet
// where both loads succeed and on one where only the second does.
func TestBpfCallHookRowLoadBytesTwoSizes(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := loadBytesTwoSizesFixture()
	in := slices.Clone(work.Programs["p"].Instructions)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := callReq("bpf_xdp_load_bytes")
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	h := plan.hooks[0]
	if h.ArgReg != 0 || h.ArgSize != 0 || h.RetPtr || h.Untrusted || h.Static || len(h.Sites) != 2 ||
		h.ArgReason != fmt.Sprintf("bpf_xdp_load_bytes is called with more than one argument size in this program (%d and 4)", loadBytesLen) {
		t.Fatalf("hook %+v", h)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 2 {
		t.Fatalf("checker: counts %+v err %v", counts, err)
	}
	plain := loadCallFixture(t, loadBytesTwoSizesFixture())
	hooked := loadHooked(t, work, plan.hooks)
	t.Cleanup(hooked.Close)
	obs := attachArgObserver(t, h.Name, hooked.Programs["p"], false, false)
	packet := make([]byte, 64)
	for i := range packet {
		packet[i] = byte(i)
	}
	for run, c := range []struct {
		data   []byte
		action uint32
	}{{packet, 2}, {packet[:48], 1}} {
		pret, pout := runCallFixture(t, plain, c.data, nil)
		ret, got := runCallFixture(t, hooked, c.data, nil)
		if ret != pret || got != pout || ret != c.action || got[1] != 0 {
			t.Fatalf("%d-byte packet: hooked %d %#x, plain %d %#x", len(c.data), ret, got, pret, pout)
		}
		calls := observed(t, obs)
		if len(calls) != 2*(run+1) {
			t.Fatalf("%d-byte packet: %d hook calls, want %d", len(c.data), len(calls), 2*(run+1))
		}
		for i, site := range h.Sites {
			if call := calls[2*run+i]; call[0] != uint64(site.SitePC) || call[1] != got[i] {
				t.Fatalf("%d-byte packet: hook call %d site %d ret %#x, want %d %#x", len(c.data), i, call[0], call[1], site.SitePC, got[i])
			}
		}
	}
}

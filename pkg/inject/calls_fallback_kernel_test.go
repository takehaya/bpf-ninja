package inject

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// sizeNotLocal puts "if size == 0 goto +0" right before the first
// instruction of spec's p that isCall accepts: the verifier still knows the
// size, while the transform sees it set in another basic block, so the
// callee gets the result-only hook (the size-conflict fallback).
func sizeNotLocal(spec *ebpf.CollectionSpec, isCall func(asm.Instruction) bool, size asm.Register) *ebpf.CollectionSpec {
	insns := spec.Programs["p"].Instructions
	jmp := asm.JEq.Imm(size, 0, "")
	jmp.Offset = 0
	spec.Programs["p"].Instructions = slices.Insert(insns, slices.IndexFunc(insns, isCall), jmp)
	return spec
}

// checkFallbackHook checks that h is the result-only pointer hook of the
// size-conflict fallback, static or arg:untrusted.
func checkFallbackHook(t *testing.T, h LookupHook, static bool) {
	t.Helper()
	if !h.RetPtr || h.ArgReg != 0 || h.ArgSize != 0 || !strings.Contains(h.ArgReason, "is not a constant set in its basic block") ||
		h.Static != static || h.Untrusted == static {
		t.Fatalf("hook %+v", h)
	}
}

// ctFallbackFixture is ctFixture with the opts size set in another basic block.
func ctFallbackFixture(t *testing.T, typ ebpf.ProgramType, dport uint16) *ebpf.CollectionSpec {
	lookup := kernelKfunc(t, ctPrefix(typ)+"lookup")
	spec := ctFixture(typ, func(name string) asm.Instruction { return kernelKfunc(t, name) }, nfConnStatusOffset(t), dport, false)
	return sizeNotLocal(spec, func(ins asm.Instruction) bool { return ins.IsKfuncCall() && ins.Constant == lookup.Constant }, asm.R5)
}

// testCallFallbackCt runs the conntrack lookup with the size-conflict
// fallback: a miss gives the hook a NULL ret and drops as the plain program
// does, a hit after the insert a non-NULL ret and passes, and both store
// what the plain program stores.
func testCallFallbackCt(t *testing.T, typ ebpf.ProgramType, dport uint16, static bool) {
	testutil.SkipIfNotRoot(t)
	name := ctPrefix(typ) + "lookup"
	req := callReq(name)
	req.Kernel, req.StaticUntrusted = kernelBTF(t), static
	coll, plan, obs := callHooked(t, ctFallbackFixture(t, typ, dport), req)
	h := plan.hooks[0]
	checkFallbackHook(t, h, static)
	if h.RetType != "nf_conn" {
		t.Fatalf("fallback hook %+v, want RetType nf_conn", h)
	}
	checkRewrite(t, ctFallbackFixture(t, typ, dport), req)
	plain := loadCallFixture(t, ctFallbackFixture(t, typ, dport))
	_, pass, drop := callVerdicts(typ)
	step := func(run int, action int32) {
		t.Helper()
		wantRet, want := runCallFixture(t, plain, make([]byte, 64), nil)
		ret, out := runCallFixture(t, coll, make([]byte, 64), nil)
		if ret != uint32(action) || wantRet != ret || out != want {
			t.Fatalf("run %d: hooked %d %#x, plain %d %#x, want action %d", run, ret, out, wantRet, want, action)
		}
		if got := lastCall(t, obs[name], run); got[0] != uint64(h.Sites[0].SitePC) || (got[1] != 0) != (action == pass) {
			t.Fatalf("run %d: hook saw site %d ret %#x", run, got[0], got[1])
		}
	}
	step(1, drop)
	kfunc := func(name string) asm.Instruction { return kernelKfunc(t, name) }
	insert := loadCallFixture(t, ctInsertProgram(typ, kfunc, dport))
	if ret, err := insert.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 1 {
		t.Fatalf("insert: %d, %v; want 1", ret, err)
	}
	step(2, pass)
}

func TestBpfCallFallbackCtXDP(t *testing.T) { testCallFallbackCt(t, ebpf.XDP, 8121, true) }
func TestBpfCallFallbackCtTC(t *testing.T)  { testCallFallbackCt(t, ebpf.SchedCLS, 8122, true) }

// The global pointer-result hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallFallbackCtUntrusted(t *testing.T) { testCallFallbackCt(t, ebpf.XDP, 8123, false) }

// skFallbackFixture is skFixture with the tuple size set in another basic block.
func skFallbackFixture(typ ebpf.ProgramType, fn asm.BuiltinFunc, dport uint16, release bool) *ebpf.CollectionSpec {
	return sizeNotLocal(skFixture(typ, fn, dport, release), func(ins asm.Instruction) bool {
		return ins.IsBuiltinCall() && ins.Constant == int64(fn)
	}, asm.R3)
}

// testCallFallbackSk hooks each socket lookup with the size-conflict
// fallback on a socket bound to 127.0.0.1: the hook sees a non-NULL ret
// while the socket exists, NULL once it is closed, and the actions match the
// plain program's.
func testCallFallbackSk(t *testing.T, typ ebpf.ProgramType, static bool) {
	testutil.SkipIfNotRoot(t)
	_, pass, drop := callVerdicts(typ)
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
			plain := loadCallFixture(t, skFallbackFixture(typ, r.fn, port, true))
			coll, plan, obs := callHooked(t, skFallbackFixture(typ, r.fn, port, true), req)
			h := plan.hooks[0]
			checkFallbackHook(t, h, static)
			for run, action := range []int32{pass, drop} {
				if run == 1 {
					if err := closer.Close(); err != nil {
						t.Fatal(err)
					}
				}
				pret, _ := runCallFixture(t, plain, make([]byte, 64), nil)
				ret, _ := runCallFixture(t, coll, make([]byte, 64), nil)
				if int32(ret) != action || pret != ret {
					t.Fatalf("run %d: hooked %d, plain %d, want %d", run, ret, pret, action)
				}
				if got := lastCall(t, obs[r.name], run+1); got[0] != uint64(h.Sites[0].SitePC) || (got[1] != 0) != (action == pass) {
					t.Fatalf("run %d: hook site %d ret %#x", run, got[0], got[1])
				}
			}
		})
	}
}

func TestBpfCallFallbackSkXDP(t *testing.T) { testCallFallbackSk(t, ebpf.XDP, true) }
func TestBpfCallFallbackSkTC(t *testing.T)  { testCallFallbackSk(t, ebpf.SchedCLS, true) }

// The global pointer-result hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallFallbackSkUntrusted(t *testing.T) { testCallFallbackSk(t, ebpf.XDP, false) }

// Without the release the program with the fallback hook is rejected as the
// plain one is, for each socket lookup and the conntrack lookup: the hook
// does not hide the acquired reference.
func TestBpfCallFallbackNoRelease(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	kernel := kernelBTF(t)
	release := kernelKfunc(t, "bpf_ct_release")
	ctNoRelease := func() *ebpf.CollectionSpec {
		spec := ctFallbackFixture(t, ebpf.XDP, 8124)
		insns := spec.Programs["p"].Instructions
		for i := range insns {
			if insns[i].IsKfuncCall() && insns[i].Constant == release.Constant {
				insns[i] = asm.Mov.Imm(asm.R1, 0)
			}
		}
		return spec
	}
	type row struct {
		name string
		spec func() *ebpf.CollectionSpec
	}
	rows := []row{{"bpf_xdp_ct_lookup", ctNoRelease}}
	for _, r := range skRows {
		rows = append(rows, row{r.name, func() *ebpf.CollectionSpec { return skFallbackFixture(ebpf.XDP, r.fn, 1, false) }})
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if coll, err := ebpf.NewCollection(r.spec()); err == nil {
				coll.Close()
				t.Fatal("plain program without the release loaded")
			}
			req := callReq(r.name)
			req.Kernel, req.StaticUntrusted = kernel, true
			work := r.spec()
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			checkFallbackHook(t, plan.hooks[0], true)
			coll, err := ebpf.NewCollection(work)
			if err == nil {
				coll.Close()
				t.Fatal("hooked program without the release loaded")
			}
			if log := fmt.Sprintf("%+v", err); !strings.Contains(log, "Unreleased reference") && !strings.Contains(log, "reference leak") {
				t.Fatalf("hooked program rejected for another reason: %+v", err)
			}
		})
	}
}

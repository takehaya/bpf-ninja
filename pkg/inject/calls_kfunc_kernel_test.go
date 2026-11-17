package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Kernel tests of the result-only hooks of kernel functions without a row:
// a scalar one, a plain pointer one, bpf_dynptr_slice, and an acquired
// pointer other than conntrack, with and without its release. Each skips
// where the running kernel lacks the kfunc or does not allow it for the
// fixture's program type; callAllHooked checks each rewrite with the
// load-time checker and compares the result with the unmodified program.

// kfuncFixture returns the kernel BTF and fixture with every kfunc of names
// resolved by id; it skips when the kernel lacks one or refuses the
// unmodified program because a kfunc is not allowed for its type.
func kfuncFixture(t *testing.T, names []string, build func(calls map[string]asm.Instruction) *ebpf.CollectionSpec) (func() *ebpf.CollectionSpec, *btf.Spec) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	kernel := kernelBTF(t)
	calls := map[string]asm.Instruction{}
	for _, name := range names {
		var fn *btf.Func
		if err := kernel.TypeByName(name, &fn); err != nil {
			t.Skipf("kernel lacks kfunc %s: %v", name, err)
		}
		calls[name] = kernelKfunc(t, name)
	}
	fixture := func() *ebpf.CollectionSpec { return build(calls) }
	coll, err := ebpf.NewCollection(fixture())
	if err != nil && strings.Contains(err.Error(), "is not allowed") {
		t.Skipf("kernel does not allow the kfuncs %v here: %v", names, err)
	}
	if err != nil {
		t.Fatalf("unmodified program: %v", err)
	}
	coll.Close()
	return fixture, kernel
}

// dynptrFromXDPFixture (XDP) builds a dynptr over the packet at fp-16 with
// bpf_dynptr_from_xdp(ctx, flags, fp-16), stores its int result in out slot 0
// and returns XDP_PASS. Flags 1 makes the call fail with -EINVAL.
func dynptrFromXDPFixture(calls map[string]asm.Instruction, flags int32) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, flags), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		calls["bpf_dynptr_from_xdp"],
		asm.Mov.Reg(asm.R7, asm.R0),
	}
	insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

// A scalar kfunc narrower than 8 bytes: the hook is global, carries
// RetSize 4, and sees the failing int result -EINVAL in its low 32 bits.
func TestBpfCallKfuncScalar(t *testing.T) {
	fixture, kernel := kfuncFixture(t, []string{"bpf_dynptr_from_xdp"}, func(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
		return dynptrFromXDPFixture(calls, 1)
	})
	req := callReq("bpf_dynptr_from_xdp")
	req.Kernel = kernel
	plan, obs, out := callAllHooked(t, fixture, req, make([]byte, 64))
	if h := plan.hooks[0]; h.RetPtr || h.Static || h.Untrusted || h.RetSize != 4 {
		t.Fatalf("hook %+v", h)
	}
	got := lastCall(t, obs["bpf_dynptr_from_xdp"], 1)[1]
	if uint32(got) != uint32(out[0]) || int32(uint32(got)) != -22 {
		t.Fatalf("hook saw ret %#x, out %#x, want -EINVAL in the low 32 bits", got, out[0])
	}
	t.Logf("ret as the hook sees it: %#x", got)
}

// kmemCacheFixture (XDP) calls bpf_get_kmem_cache(0), which returns NULL,
// stores 1 in out slot 0 when the result is not NULL and returns XDP_PASS.
func kmemCacheFixture(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R1, 0),
		calls["bpf_get_kmem_cache"],
		asm.Mov.Imm(asm.R7, 0),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.Mov.Imm(asm.R7, 1),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

// A plain pointer kfunc (untrusted struct pointer, not acquired).
func TestBpfCallKfuncPointer(t *testing.T) {
	fixture, kernel := kfuncFixture(t, []string{"bpf_get_kmem_cache"}, kmemCacheFixture)
	testPointerKind(t, fixture, "bpf_get_kmem_cache", kernel)
}

// dynptrSliceFixture (XDP) builds a dynptr over the packet, takes a 4-byte
// slice at offset 0 with bpf_dynptr_slice (no buffer), stores the u32 it
// points to, or zero for NULL, in out slot 0 and returns XDP_PASS.
func dynptrSliceFixture(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, 0), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		calls["bpf_dynptr_from_xdp"],
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 4),
		calls["bpf_dynptr_slice"],
		asm.Mov.Imm(asm.R7, 0),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.LoadMem(asm.R7, asm.R0, 0, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

// bpf_dynptr_slice returns void *, which the verifier makes packet memory:
// it takes the pointer form.
func TestBpfCallKfuncDynptrSlice(t *testing.T) {
	fixture, kernel := kfuncFixture(t, []string{"bpf_dynptr_from_xdp", "bpf_dynptr_slice"}, dynptrSliceFixture)
	testPointerKind(t, fixture, "bpf_dynptr_slice", kernel)
}

// taskFixture (tc) acquires the task of pid 1 with bpf_task_from_pid, stores
// 1 in out slot 0 when it got one and, with release, releases it with
// bpf_task_release; it returns TC_ACT_OK. Without the release the reference
// leaks and the kernel must refuse the program.
func taskFixture(release bool) func(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
	return func(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R1, 1),
			calls["bpf_task_from_pid"],
			asm.Mov.Imm(asm.R7, 0),
			asm.JEq.Imm(asm.R0, 0, "store"),
			asm.Mov.Imm(asm.R7, 1),
		}
		if release {
			insns = append(insns, asm.Mov.Reg(asm.R1, asm.R0), calls["bpf_task_release"])
		}
		insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("store"))
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
		return callFixtureSpec(ebpf.SchedCLS, insns)
	}
}

// An acquired pointer other than conntrack, released by the program.
func TestBpfCallKfuncAcquired(t *testing.T) {
	fixture, kernel := kfuncFixture(t, []string{"bpf_task_from_pid", "bpf_task_release"}, taskFixture(true))
	testPointerKind(t, fixture, "bpf_task_from_pid", kernel)
}

// Without the release both the unmodified and the hooked program are refused
// in both forms: the hook does not hide the leaked reference.
func TestBpfCallKfuncAcquiredMissingRelease(t *testing.T) {
	_, kernel := kfuncFixture(t, []string{"bpf_task_from_pid", "bpf_task_release"}, taskFixture(true))
	calls := map[string]asm.Instruction{"bpf_task_from_pid": kernelKfunc(t, "bpf_task_from_pid")}
	leak := func() *ebpf.CollectionSpec { return taskFixture(false)(calls) }
	if _, err := ebpf.NewCollection(leak()); err == nil || !strings.Contains(err.Error(), "reference") {
		t.Fatalf("unmodified program without release: %v", err)
	}
	for _, static := range []bool{true, false} {
		work := leak()
		req := callReq("bpf_task_from_pid")
		req.StaticUntrusted, req.Kernel = static, kernel
		plan, err := transformLookup(work, req)
		if err != nil || len(plan.hooks) != 1 {
			t.Fatalf("static %v: hooks %+v err %v", static, plan.hooks, err)
		}
		coll, err := ebpf.NewCollection(work)
		if err == nil {
			coll.Close()
			t.Fatalf("static %v: the hooked program without release loaded", static)
		}
		var ve *ebpf.VerifierError
		if !errors.As(err, &ve) {
			t.Fatalf("static %v: %v", static, err)
		}
		t.Logf("static %v: refused: %v", static, err)
	}
}

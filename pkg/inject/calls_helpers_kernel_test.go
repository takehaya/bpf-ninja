package inject

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Kernel tests of the pointer helpers package 2 left off that an XDP or tc
// program can call, in the form of calls_all_kernel_test.go: testPointerKind
// loads the static and the global form, checks each with the load-time
// checker and compares one run with the unmodified program. A test skips
// where the running kernel does not offer the helper to the fixture's
// program type.

// helperOffered skips unless the unmodified fixture loads; the kernel
// refuses a helper it does not offer to the program type with "unknown func"
// or "cannot use helper".
func helperOffered(t *testing.T, fixture func() *ebpf.CollectionSpec) func() *ebpf.CollectionSpec {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	coll, err := ebpf.NewCollection(fixture())
	if err != nil && (strings.Contains(err.Error(), "unknown func") || strings.Contains(err.Error(), "cannot use helper")) {
		t.Skipf("kernel does not offer the helper here: %v", err)
	}
	if err != nil {
		t.Fatalf("unmodified program: %v", err)
	}
	coll.Close()
	return fixture
}

// sockCommonFixture (tc) passes skb->sk, when set, to fn and stores 1 in out
// slot 0 when fn returned a socket; it returns TC_ACT_OK.
func sockCommonFixture(fn asm.BuiltinFunc) func() *ebpf.CollectionSpec {
	return func() *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R7, 0),
			asm.LoadMem(asm.R1, asm.R6, 168, asm.DWord), // __sk_buff.sk
			asm.JEq.Imm(asm.R1, 0, "store"),
			fn.Call(),
			asm.JEq.Imm(asm.R0, 0, "store"),
			asm.Mov.Imm(asm.R7, 1),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
		}
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
		return callFixtureSpec(ebpf.SchedCLS, insns)
	}
}

func testSockCommon(t *testing.T, fn asm.BuiltinFunc, name string) {
	testPointerKind(t, helperOffered(t, sockCommonFixture(fn)), name, nil)
}

func TestBpfCallAllPointerGetListenerSock(t *testing.T) {
	testSockCommon(t, asm.FnGetListenerSock, "bpf_get_listener_sock")
}
func TestBpfCallAllPointerSkcToTcp6Sock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToTcp6Sock, "bpf_skc_to_tcp6_sock")
}
func TestBpfCallAllPointerSkcToTcpSock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToTcpSock, "bpf_skc_to_tcp_sock")
}
func TestBpfCallAllPointerSkcToTcpTimewaitSock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToTcpTimewaitSock, "bpf_skc_to_tcp_timewait_sock")
}
func TestBpfCallAllPointerSkcToTcpRequestSock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToTcpRequestSock, "bpf_skc_to_tcp_request_sock")
}
func TestBpfCallAllPointerSkcToUdp6Sock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToUdp6Sock, "bpf_skc_to_udp6_sock")
}
func TestBpfCallAllPointerSkcToUnixSock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToUnixSock, "bpf_skc_to_unix_sock")
}
func TestBpfCallAllPointerSkcToMptcpSock(t *testing.T) {
	testSockCommon(t, asm.FnSkcToMptcpSock, "bpf_skc_to_mptcp_sock")
}

// skStorageFixture (tc) gets skb->sk's full socket and its sk_storage entry
// without creating one, stores 1 in out slot 0 when there is one and returns
// TC_ACT_OK.
func skStorageFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R7, 0),
		asm.LoadMem(asm.R1, asm.R6, 168, asm.DWord), // __sk_buff.sk
		asm.JEq.Imm(asm.R1, 0, "store"),
		asm.FnSkFullsock.Call(),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.Mov.Reg(asm.R2, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("storage"),
		asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0),
		asm.FnSkStorageGet.Call(),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.Mov.Imm(asm.R7, 1),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
	spec := callFixtureSpec(ebpf.SchedCLS, insns)
	spec.Maps["storage"] = localStorageMap(ebpf.SkStorage)
	return spec
}

// localStorageMap is a socket, task or cgroup storage map of int to u64.
func localStorageMap(typ ebpf.MapType) *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "storage", Type: typ, KeySize: 4, ValueSize: 8, Flags: 1, // BPF_F_NO_PREALLOC
		Key: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Value: &btf.Int{Name: "u64", Size: 8}}
}

func TestBpfCallAllPointerSkStorageGet(t *testing.T) {
	testPointerKind(t, helperOffered(t, skStorageFixture), "bpf_sk_storage_get", nil)
}

// perCPUFixture (XDP) reads the int bpf_prog_active of CPU 0 through
// bpf_per_cpu_ptr, stores 1 in out slot 0 when it got a pointer and returns
// XDP_PASS; a typed ksym of the running kernel, so it needs kernel BTF.
func perCPUFixture(t *testing.T) func() *ebpf.CollectionSpec {
	kernel := kernelBTF(t)
	var v *btf.Var
	if err := kernel.TypeByName("bpf_prog_active", &v); err != nil {
		t.Skipf("kernel BTF has no bpf_prog_active: %v", err)
	}
	id, err := kernel.TypeID(v)
	if err != nil {
		t.Fatal(err)
	}
	return func() *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R7, 0),
			{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R1, Src: asm.R3, Constant: int64(id)}, // BPF_PSEUDO_BTF_ID
			asm.Mov.Imm(asm.R2, 0),
			asm.FnPerCpuPtr.Call(),
			asm.JEq.Imm(asm.R0, 0, "store"),
			asm.LoadMem(asm.R8, asm.R0, 0, asm.Word),
			asm.Mov.Imm(asm.R7, 1),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
		}
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
		return callFixtureSpec(ebpf.XDP, insns)
	}
}

func TestBpfCallAllPointerPerCpuPtr(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testPointerKind(t, helperOffered(t, perCPUFixture(t)), "bpf_per_cpu_ptr", nil)
}

// dynptrDataFixture (XDP) makes a dynptr over the first 8 bytes of out's
// value with bpf_dynptr_from_mem, reads 4 bytes through bpf_dynptr_data,
// stores them, or zero for NULL, in out slot 1 and returns XDP_PASS.
func dynptrDataFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMapValue(asm.R1, 0, 0).WithReference("out"), asm.Mov.Imm(asm.R2, 8), asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -16),
		asm.FnDynptrFromMem.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 4),
		asm.FnDynptrData.Call(),
		asm.Mov.Imm(asm.R7, 0),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.LoadMem(asm.R7, asm.R0, 0, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(1, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

func TestBpfCallAllPointerDynptrData(t *testing.T) {
	testPointerKind(t, helperOffered(t, dynptrDataFixture), "bpf_dynptr_data", nil)
}

// currentTaskFixture (tc) takes the current task with
// bpf_get_current_task_btf and then, by what, its registers
// (bpf_task_pt_regs) or its task_storage entry without creating one
// (bpf_task_storage_get); it stores 1 in out slot 0 and returns TC_ACT_OK.
func currentTaskFixture(what asm.BuiltinFunc) func() *ebpf.CollectionSpec {
	return func() *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R7, 0),
			asm.FnGetCurrentTaskBtf.Call(),
		}
		switch what {
		case asm.FnTaskPtRegs:
			insns = append(insns, asm.Mov.Reg(asm.R1, asm.R0), asm.FnTaskPtRegs.Call())
		case asm.FnTaskStorageGet:
			insns = append(insns, asm.Mov.Reg(asm.R2, asm.R0), asm.LoadMapPtr(asm.R1, 0).WithReference("storage"),
				asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.FnTaskStorageGet.Call())
		}
		insns = append(insns, asm.JEq.Imm(asm.R0, 0, "store"), asm.Mov.Imm(asm.R7, 1), asm.Mov.Imm(asm.R0, 0).WithSymbol("store"))
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
		spec := callFixtureSpec(ebpf.SchedCLS, insns)
		if what == asm.FnTaskStorageGet {
			spec.Maps["storage"] = localStorageMap(ebpf.TaskStorage)
		}
		return spec
	}
}

func TestBpfCallAllPointerGetCurrentTaskBtf(t *testing.T) {
	testPointerKind(t, helperOffered(t, currentTaskFixture(0)), "bpf_get_current_task_btf", nil)
}
func TestBpfCallAllPointerTaskPtRegs(t *testing.T) {
	testPointerKind(t, helperOffered(t, currentTaskFixture(asm.FnTaskPtRegs)), "bpf_task_pt_regs", nil)
}

// tc may call bpf_task_storage_get from 6.18 on; older kernels refuse the
// unmodified fixture, and the test skips with the kernel's message.
func TestBpfCallAllPointerTaskStorageGet(t *testing.T) {
	testPointerKind(t, helperOffered(t, currentTaskFixture(asm.FnTaskStorageGet)), "bpf_task_storage_get", nil)
}

// cgrpStorageFixture (tc) acquires the root cgroup (id 1) with the kfunc
// bpf_cgroup_from_id, gets its cgrp_storage entry without creating one,
// releases the cgroup with bpf_cgroup_release, stores 1 in out slot 0 when
// there was an entry and returns TC_ACT_OK.
func cgrpStorageFixture(calls map[string]asm.Instruction) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R7, 0),
		asm.Mov.Imm(asm.R1, 1),
		calls["bpf_cgroup_from_id"],
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.Mov.Reg(asm.R2, asm.R0), asm.LoadMapPtr(asm.R1, 0).WithReference("storage"),
		asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0),
		asm.FnCgrpStorageGet.Call(),
		asm.JEq.Imm(asm.R0, 0, "release"),
		asm.Mov.Imm(asm.R7, 1),
		asm.Mov.Reg(asm.R1, asm.R8).WithSymbol("release"),
		calls["bpf_cgroup_release"],
		asm.Mov.Imm(asm.R0, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
	spec := callFixtureSpec(ebpf.SchedCLS, insns)
	spec.Maps["storage"] = localStorageMap(ebpf.CgroupStorage)
	return spec
}

func TestBpfCallAllPointerCgrpStorageGet(t *testing.T) {
	fixture, kernel := kfuncFixture(t, []string{"bpf_cgroup_from_id", "bpf_cgroup_release"}, cgrpStorageFixture)
	testPointerKind(t, fixture, "bpf_cgrp_storage_get", kernel)
}

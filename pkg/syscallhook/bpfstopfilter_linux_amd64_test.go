//go:build linux && amd64

package syscallhook

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// The filter runs on seccomp_data. The kernel loads its 32-bit words in host
// order and this VM loads them big-endian, so each word is stored big-endian
// here: the filter sees the same values as in the kernel.
func runStopFilter(t *testing.T, arch, nr uint32, arg0 uint64) uint32 {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(bpfStopFilter))
	for i, f := range bpfStopFilter {
		raw[i] = bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}
	}
	prog, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("filter does not disassemble")
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:], nr)
	binary.BigEndian.PutUint32(data[4:], arch)
	binary.BigEndian.PutUint32(data[16:], uint32(arg0))
	binary.BigEndian.PutUint32(data[20:], uint32(arg0>>32))
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(ret)
}

func TestBPFStopFilterCommands(t *testing.T) {
	trace := uint32(unix.SECCOMP_RET_TRACE | seccompDataBPF)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	const x86 = unix.AUDIT_ARCH_X86_64
	for _, tc := range []struct {
		name string
		arch uint32
		nr   uint32
		arg0 uint64
		want uint32
	}{
		{"prog load", x86, unix.SYS_BPF, unix.BPF_PROG_LOAD, trace},
		{"btf load", x86, unix.SYS_BPF, unix.BPF_BTF_LOAD, trace},
		{"prog load with common attrs", x86, unix.SYS_BPF, unix.BPF_PROG_LOAD | bpfCommonAttrs, trace},
		{"btf load with common attrs", x86, unix.SYS_BPF, unix.BPF_BTF_LOAD | bpfCommonAttrs, trace},
		{"prog load, high bits of args[0]", x86, unix.SYS_BPF, 0xffffffff<<32 | unix.BPF_PROG_LOAD, trace},
		{"map create", x86, unix.SYS_BPF, unix.BPF_MAP_CREATE, allow},
		{"map update", x86, unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, allow},
		{"map delete", x86, unix.SYS_BPF, unix.BPF_MAP_DELETE_ELEM, allow},
		{"map create with common attrs", x86, unix.SYS_BPF, unix.BPF_MAP_CREATE | bpfCommonAttrs, allow},
		{"info by fd", x86, unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, allow},
		{"prog attach", x86, unix.SYS_BPF, unix.BPF_PROG_ATTACH, allow},
		{"other flag bit", x86, unix.SYS_BPF, unix.BPF_PROG_LOAD | 1<<17, allow},
		{"seccomp", x86, unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, allow},
		{"prctl PR_SET_SECCOMP", x86, unix.SYS_PRCTL, unix.PR_SET_SECCOMP, allow},
		{"getppid", x86, unix.SYS_GETPPID, 0, allow},
		{"x32 bpf", x86, 0x40000000 | unix.SYS_BPF, unix.BPF_PROG_LOAD, allow},
		{"i386 bpf", unix.AUDIT_ARCH_I386, 357, unix.BPF_PROG_LOAD, allow},
		{"i386 nr equal to x86-64 bpf", unix.AUDIT_ARCH_I386, unix.SYS_BPF, unix.BPF_PROG_LOAD, allow},
	} {
		if got := runStopFilter(t, tc.arch, tc.nr, tc.arg0); got != tc.want {
			t.Errorf("%s: %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

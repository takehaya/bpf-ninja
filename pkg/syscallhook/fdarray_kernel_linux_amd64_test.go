//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

const fdArrayChild = "SYSCALLHOOK_FDARRAY_CHILD"

// TestBpfFdArray loads a lookup program with a raw BPF_PROG_LOAD that carries
// fd_array = [map fd]: "plain" leaves the instructions alone and is hooked,
// "cnt" also sets fd_array_cnt (6.14 and later), and "idx" names the map by
// index (BPF_PSEUDO_MAP_IDX), which the supervisor refuses to rewrite.
func TestBpfFdArray(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if mode := os.Getenv(fdArrayChild); mode != "" {
		loadFdArrayProgram(t, mode)
		return
	}
	cases := []struct{ mode, want string }{{"plain", "hook=true"}, {"idx", "hook=false"}}
	if k := runningKernelInfo(); k.Major > 6 || k.Major == 6 && k.Minor >= 14 {
		cases = append(cases, struct{ mode, want string }{"cnt", "hook=true"})
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv(fdArrayChild, tc.mode)
			out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()
			var logs bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var refusals []Refusal
			code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestBpfFdArray$"}, Options{Rules: []Rule{testRule()}, Stdout: out, Stderr: out, Log: &logs,
				OnRefuse: func(r Refusal) { refusals = append(refusals, r) }})
			data, _ := os.ReadFile(out.Name())
			t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
			if err != nil || code != 0 || !strings.Contains(string(data), tc.want) {
				t.Fatalf("code=%d err=%v, want %s", code, err, tc.want)
			}
			if tc.mode == "idx" && !strings.Contains(logs.String(), "map load by fd_array index") {
				t.Fatal("no fd_array index refusal logged")
			}
			// The load left unchanged at its entry stop is reported once its
			// exit stop shows that the original loaded.
			want := 0
			if tc.mode == "idx" {
				want = 1
			}
			if len(refusals) != want || want == 1 && (refusals[0].Cause != "transform" || refusals[0].Outcome != "original_loaded" ||
				!strings.Contains(refusals[0].Reason, "map load by fd_array index")) {
				t.Fatalf("refusals %+v", refusals)
			}
		})
	}
	// The same raw loader runs unsupervised.
	cmd := exec.Command(os.Args[0], "-test.run=^TestBpfFdArray$")
	cmd.Env = append(os.Environ(), fdArrayChild+"=idx")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "hook=false") {
		t.Fatalf("baseline loader: %v\n%s", err, out)
	}
}

func bpfRaw(t *testing.T, cmd uintptr, attr []byte) int {
	t.Helper()
	fd, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		t.Fatalf("bpf(%d): %v", cmd, errno)
	}
	return int(fd)
}

func loadFdArrayProgram(t *testing.T, mode string) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("loader lookup")), fn)
	builder, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	funcInfo, lineInfo, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	btfAttr := make([]byte, 32)
	put64(btfAttr, 0, uint64(uintptr(unsafe.Pointer(&blob[0]))))
	put32(btfAttr, 16, uint32(len(blob)))
	btfFD := bpfRaw(t, unix.BPF_BTF_LOAD, btfAttr)
	runtime.KeepAlive(blob)
	defer func() { _ = unix.Close(btfFD) }()
	var code bytes.Buffer
	if err := insns.Marshal(&code, wire); err != nil {
		t.Fatal(err)
	}
	raw := code.Bytes()
	if mode == "idx" {
		ld := 3 * 8 // the map load is the fourth instruction
		raw[ld+1] = raw[ld+1]&0x0f | 5<<4
		put32(raw, ld+4, 0)
	}
	fdArray := []uint32{uint32(m.FD())}
	license := []byte("GPL\x00")
	attr := make([]byte, 152)
	put32(attr, 0, uint32(ebpf.XDP))
	put32(attr, 4, uint32(len(raw)/8))
	put64(attr, 8, uint64(uintptr(unsafe.Pointer(&raw[0]))))
	put64(attr, 16, uint64(uintptr(unsafe.Pointer(&license[0]))))
	copy(attr[48:64], "p")
	put32(attr, 72, uint32(btfFD))
	put32(attr, 76, 8)
	put64(attr, 80, uint64(uintptr(unsafe.Pointer(&funcInfo[0]))))
	put32(attr, 88, uint32(len(funcInfo)/8))
	put32(attr, 92, 16)
	put64(attr, 96, uint64(uintptr(unsafe.Pointer(&lineInfo[0]))))
	put32(attr, 104, uint32(len(lineInfo)/16))
	put64(attr, 120, uint64(uintptr(unsafe.Pointer(&fdArray[0]))))
	if mode == "cnt" {
		put32(attr, 148, 1)
	}
	fd := bpfRaw(t, unix.BPF_PROG_LOAD, attr)
	runtime.KeepAlive(raw)
	runtime.KeepAlive(license)
	runtime.KeepAlive(funcInfo)
	runtime.KeepAlive(lineInfo)
	runtime.KeepAlive(fdArray)
	p, err := ebpf.NewProgramFromFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := info.FuncInfos()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range funcs {
		found = found || strings.HasPrefix(f.Func.Name, "lookup_hook")
	}
	action, _, err := p.Test(make([]byte, 64))
	if err != nil || action != 2 {
		t.Fatalf("BPF_PROG_TEST_RUN: action=%d err=%v", action, err)
	}
	fmt.Printf("hook=%v action=%d\n", found, action)
}

//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"golang.org/x/sys/unix"
)

// The child is an ordinary cilium/ebpf loader. It has no injector calls and
// reports kernel program metadata; merely producing transformed bytes cannot
// satisfy this test. No interface attachment, pin, or global setting is used.
func TestIntegrationLoader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if expected := os.Getenv("SYSCALLHOOK_INTEGRATION_CHILD"); expected != "" {
		loadIntegrationProgram(t, expected)
		return
	}
	// Prove the same loader succeeds without the supervisor and has no hook.
	t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", "plain")
	child := []string{os.Args[0], "-test.run=^TestIntegrationLoader$"}
	if out, err := exec.Command(child[0], child[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("baseline loader: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name, expected string
		closed         bool
		change         func(*Rule)
	}{
		{"kernel-name", "hook", false, func(r *Rule) {}},
		{"func-info-name", "hook", false, func(r *Rule) { r.Program = "entry_with_long_name" }},
		{"fail-open", "plain", false, func(r *Rule) { r.Map = "missing" }},
		{"fail-closed", "refused", true, func(r *Rule) { r.Map = "missing" }},
		{"unmatched", "plain", true, func(r *Rule) { r.Program = "unmatched" }},
		// The loader's audit is wrong: its key store aliases the stack, so a
		// bound of 0 passes the transform, the ctx spill is overwritten and the
		// verifier rejects the transformed program.
		{"bad-audit-open", "plain-alias", false, func(r *Rule) { *r.StackLowestOffset = 0 }},
		{"bad-audit-closed", "refused-alias", true, func(r *Rule) { *r.StackLowestOffset = 0 }},
		{"auto", "hook", true, func(r *Rule) { r.Auto, r.Map = true, "" }},
		{"entry-only", "hook", true, func(r *Rule) { r.Entry, r.Map = true, "" }},
		// The loader's map is BPF_F_RDONLY_PROG, whose hook becomes static.
		{"static-untrusted", "hook-rdonly", true, func(r *Rule) { r.Auto, r.Map, r.StaticUntrusted = true, "", true }},
		// Static, so the dispatch hook loads on kernels without arg:untrusted
		// too; TestBpfDispatch covers the untrusted form across the matrix.
		{"dispatch", "hook", true, func(r *Rule) { r.Auto, r.Map, r.Entry, r.Dispatch, r.StaticUntrusted = true, "", true, true, true }},
		{"maps", "hook", true, func(r *Rule) { r.Auto, r.Map, r.Maps = true, "", []string{"sessions"} }},
		{"maps-missing", "refused", true, func(r *Rule) { r.Auto, r.Map, r.Maps = true, "", []string{"missing"} }},
		// The loader first inserts the present key with BPF_NOEXIST, which
		// fails; ops instruments only that update.
		{"ops-update", "hook-update", true, func(r *Rule) { r.Auto, r.Map, r.Ops = true, "", []string{"update"} }},
		// The discover cases also set OnDiscover; discover-only has no rule.
		{"discover-auto", "hook", true, func(r *Rule) { r.Auto, r.Map = true, "" }},
		{"discover-only", "plain", true, func(r *Rule) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", tc.expected)
			out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()
			rule := testRule()
			tc.change(&rule)
			var logs bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var injected []Injection
			var discovered []Discovery
			opts := Options{Rules: []Rule{rule}, FailClosed: tc.closed, Stdout: out, Stderr: out, Log: &logs,
				OnInject: func(inj Injection) { injected = append(injected, inj) }}
			discover := strings.HasPrefix(tc.name, "discover")
			if discover {
				opts.OnDiscover = func(d Discovery) { discovered = append(discovered, d) }
			}
			if tc.name == "discover-only" {
				opts.Rules = nil
			}
			code, err := Run(ctx, child, opts)
			data, _ := os.ReadFile(out.Name())
			t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if strings.HasPrefix(tc.expected, "hook") && !strings.Contains(logs.String(), "injected hook") {
				t.Fatal("no successful injection reported")
			}
			// OnInject reports exactly the successful injections, with the
			// program ID the loader sees.
			if hooked := strings.HasPrefix(tc.expected, "hook"); hooked != (len(injected) == 1) || len(injected) > 1 {
				t.Fatalf("OnInject calls: %+v", injected)
			} else if hooked {
				inj := injected[0]
				if inj.Program != "p" || inj.Func != "entry_with_long_name" || inj.Type != ebpf.XDP || len(inj.Hooks) == 0 ||
					!strings.Contains(string(data), fmt.Sprintf("prog_id=%d\n", inj.ProgID)) || inj.ProgID == 0 {
					t.Fatalf("injection %+v does not match the loader", inj)
				}
			}
			// OnDiscover sees the original program once, with its one lookup.
			if discover != (len(discovered) == 1) || len(discovered) > 1 {
				t.Fatalf("OnDiscover calls: %+v", discovered)
			} else if discover {
				d := discovered[0]
				if d.Program != "p" || d.Func != "entry_with_long_name" || d.Type != ebpf.XDP || len(d.Lookups) != 1 ||
					d.Lookups[0].MapName != "sessions" || d.Lookups[0].Reason != "" || d.Maps["sessions"] != ebpf.Hash ||
					len(d.Calls) != 1 || d.Calls[0] != d.Lookups[0] {
					t.Fatalf("discovery %+v does not match the loader", d)
				}
			}
			if tc.name == "maps-missing" && !strings.Contains(logs.String(), `Maps name "missing" matches no lookup`) {
				t.Fatal("no refusal of the unknown map name reported")
			}
			if tc.expected == "hook-rdonly" && !strings.Contains(logs.String(), ", static") {
				t.Fatal("no static hook reported")
			}
			if strings.HasPrefix(tc.name, "bad-audit") {
				if !strings.Contains(logs.String(), "transformed PROG_LOAD") {
					t.Fatal("no verifier rejection of the transformed program reported")
				}
				// The rejection names the attempted hooks; the hook is typed,
				// so no arg:untrusted hint follows.
				if !strings.Contains(logs.String(), `attempted hook "`) {
					t.Fatal("rejection does not name the attempted hooks")
				}
				if strings.Contains(logs.String(), "arg:untrusted") {
					t.Fatal("arg:untrusted hint for a typed hook")
				}
			}
			if tc.name == "ops-update" && (len(injected) != 1 || len(injected[0].Hooks) != 1 ||
				injected[0].Hooks[0].Name != "lookup_hook_sessions_update" || injected[0].Hooks[0].Kind != inject.HookUpdate) {
				t.Fatalf("update hook not injected: %+v", injected)
			}
			if tc.name == "dispatch" && !strings.Contains(logs.String(), ", static, dispatch") {
				t.Fatal("no dispatch hook reported")
			}
		})
	}
}

func loadIntegrationProgram(t *testing.T, expected string) {
	t.Helper()
	// A "-alias" variant stores the key through a stack alias, so a bound of 0
	// passes the transform but the ctx spill is overwritten.
	alias := strings.HasSuffix(expected, "-alias")
	expected = strings.TrimSuffix(expected, "-alias")
	u32 := &btf.Int{Name: "u32", Size: 4}
	spec := &ebpf.MapSpec{Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32}
	mapTypes := strings.Contains(expected, "map-types")
	if mapTypes {
		spec.ValueSize = 8
		spec.Key, spec.Value = nil, nil
		if expected == "refused-map-types" {
			spec.Key = u32
			spec.Value = &btf.Struct{Name: "record", Size: 8, Members: []btf.Member{{Name: "identity", Type: u32}, {Name: "action", Type: u32, Offset: 32}}}
		}
	}
	if expected == "hook-rdonly" {
		spec.Flags = unix.BPF_F_RDONLY_PROG
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	var value any = uint32(2)
	if mapTypes {
		value = struct{ Identity, Action uint32 }{7, 2}
	}
	if err := m.Put(uint32(0), value); err != nil {
		t.Fatal(err)
	}
	fn := &btf.Func{Name: "entry_with_long_name", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	store := asm.StoreImm(asm.RFP, -4, 0, asm.Word)
	if alias {
		store = asm.StoreImm(asm.R2, 0, 0, asm.Word)
	}
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	if expected == "hook-update" {
		insns = append(insns,
			asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.StoreImm(asm.RFP, -8, 2, asm.Word),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
			asm.Mov.Imm(asm.R4, unix.BPF_NOEXIST),
			asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapUpdateElem.Call())
	}
	valueOffset := int16(0)
	if mapTypes {
		valueOffset = 4
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		store,
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R0, asm.R0, valueOffset, asm.Word), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
	)
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("loader lookup")), fn)
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if expected == "refused" || expected == "refused-map-types" {
		if err == nil {
			_ = p.Close()
			t.Fatal("fail-closed load unexpectedly succeeded")
		}
		fmt.Println("matched load refused")
		return
	}
	if err != nil {
		t.Fatalf("program load: %+v", err)
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
		// Auto and entry rules name the hook lookup_hook_sessions or lookup_hook_entry.
		if strings.HasPrefix(f.Func.Name, "lookup_hook") {
			found = true
			if expected == "hook-map-types" {
				proto := f.Func.Type.(*btf.FuncProto)
				if len(proto.Params) != 3 {
					t.Fatalf("hook params: %+v", proto.Params)
				}
				ptr, ok := proto.Params[2].Type.(*btf.Pointer)
				if !ok {
					t.Fatalf("value is not a pointer: %v", proto.Params[2].Type)
				}
				v, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
				if !ok || v.Name != "record" || len(v.Members) != 2 || v.Members[0].Name != "identity" || v.Members[1].Name != "action" {
					t.Fatalf("supplied record not present in kernel hook BTF: %v", ptr.Target)
				}
			}
		}
	}
	if found != strings.HasPrefix(expected, "hook") {
		t.Fatalf("kernel func_info hook=%v, expected %s; funcs=%+v", found, expected, funcs)
	}
	action, _, err := p.Test(make([]byte, 64))
	if err != nil || action != 2 {
		t.Fatalf("BPF_PROG_TEST_RUN: action=%d err=%v", action, err)
	}
	id, _ := info.ID()
	fmt.Printf("kernel hook=%v, action=%d, functions=%d, prog_id=%d\n", found, action, len(funcs), id)
}

func TestIntegrationMapTypes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if expected := os.Getenv("SYSCALLHOOK_MAP_TYPES_CHILD"); expected != "" {
		loadIntegrationProgram(t, expected)
		return
	}
	t.Run("extract-btf-id", integrationExtractMapBTF)
	// VMs can receive a precompiled fixture; local runs compile it with the
	// usual clang availability policy.
	elf := os.Getenv("SYSCALLHOOK_MAP_TYPES_ELF")
	if elf == "" {
		src, err := os.ReadFile("testdata/maptypes/program.c")
		if err != nil {
			t.Fatal(err)
		}
		elf = testutil.CompileBPFSource(t, string(src))
	}
	elf, err := filepath.Abs(elf)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(elf)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	for _, expected := range []string{"hook-map-types", "refused-map-types"} {
		t.Run(expected, func(t *testing.T) {
			t.Setenv("SYSCALLHOOK_MAP_TYPES_CHILD", expected)
			rule := testRule()
			rule.MapBTF = &MapBTF{ELF: elf, SHA256: digest}
			var logs bytes.Buffer
			var injected []Injection
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()
			code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestIntegrationMapTypes$", "-test.v"}, Options{
				Rules: []Rule{rule}, FailClosed: true, Log: &logs, Stdout: out, Stderr: out,
				OnInject: func(inj Injection) { injected = append(injected, inj) },
			})
			childOut, _ := os.ReadFile(out.Name())
			t.Logf("supervisor:\n%sloader:\n%s", &logs, childOut)
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if expected == "hook-map-types" {
				if len(injected) != 1 || !strings.Contains(logs.String(), "types from ELF sha256 "+digest[:12]+": key \"u32\", value \"record\"") {
					t.Fatalf("supplementation not reported: %+v", injected)
				}
			} else if len(injected) != 0 || !strings.Contains(logs.String(), "already has BTF") {
				t.Fatalf("existing-BTF refusal missing: %+v", injected)
			}
		})
	}
}

// Observe extractRaw against a real stopped loader's map info independently of
// the nonnil Key/Value refusal, so removing BTFID extraction is detectable.
func integrationExtractMapBTF(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	t.Setenv("SYSCALLHOOK_MAP_TYPES_CHILD", "plain")
	cmd := exec.Command(os.Args[0], "-test.run=^TestIntegrationMapTypes$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(20*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	defer func() {
		_ = cmd.Process.Kill()
		for {
			var status unix.WaitStatus
			tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOTHREAD, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				break
			}
			if status.Stopped() {
				_ = unix.PtraceCont(tid, int(unix.SIGKILL))
			}
		}
		_ = cmd.Process.Release()
	}()
	pid := cmd.Process.Pid
	status, err := waitThread(pid)
	if err != nil || !status.Stopped() {
		t.Fatalf("initial stop: %v, %v", status, err)
	}
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_EXITKILL); err != nil {
		t.Fatal(err)
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatal(err)
	}
	for {
		var status unix.WaitStatus
		tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOTHREAD, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if status.Exited() || status.Signaled() {
			if tid == pid {
				t.Fatal("loader exited before program load")
			}
			continue
		}
		if !status.Stopped() {
			continue
		}
		if status.StopSignal() != unix.SIGTRAP|0x80 {
			if err := unix.PtraceSyscall(tid, 0); err != nil && err != unix.ESRCH {
				t.Fatal(err)
			}
			continue
		}
		op, _, err := syscallStop(tid)
		if err != nil {
			t.Fatal(err)
		}
		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(tid, &regs); err != nil {
			t.Fatal(err)
		}
		if op != 1 || regs.Orig_rax != unix.SYS_BPF || regs.Rdi != unix.BPF_PROG_LOAD {
			if err := unix.PtraceSyscall(tid, 0); err != nil && err != unix.ESRCH {
				t.Fatal(err)
			}
			continue
		}
		attr, err := readMemory(tid, regs.Rsi, regs.Rdx)
		if err != nil {
			t.Fatal(err)
		}
		if len(attr) < 64 || cstring(attr[48:64]) != "p" {
			if err := unix.PtraceSyscall(tid, 0); err != nil && err != unix.ESRCH {
				t.Fatal(err)
			}
			continue
		}
		if err := parseProgAttr(attr); err != nil {
			t.Fatalf("program attr: %v", err)
		}
		r, err := beginRemote(tid, regs, true)
		if err != nil {
			t.Fatalf("begin remote: %v", err)
		}
		raw, err := extractRaw(r, attr, nil)
		if err != nil {
			t.Fatalf("extractRaw: %v", err)
		}
		if len(raw.Maps) != 1 {
			t.Fatalf("maps: %+v", raw.Maps)
		}
		for _, m := range raw.Maps {
			if m.Name != "sessions" || m.BTFID == 0 || m.Key == nil || m.Value == nil {
				t.Fatalf("lost live map BTF: %+v", m)
			}
			t.Logf("extractRaw: map %s BTFID=%d, key=%s, value=%s", m.Name, m.BTFID, m.Key.TypeName(), m.Value.TypeName())
		}
		return
	}
}

package program

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

const fexitLayoutSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
#define RET 2
#define KEEP(x) asm volatile("" : : "r"(x))
volatile __u32 arg_a = 99;
volatile __u32 arg_b = 77;
volatile int results;
__attribute__((noinline)) int one(struct xdp_md *ctx) {
    KEEP(ctx); return RET;
}
__attribute__((noinline)) int two(struct xdp_md *ctx, __u32 a) {
    KEEP(ctx); KEEP(a); return a == 99 ? RET : 0;
}
__attribute__((noinline)) int three(struct xdp_md *ctx, __u32 a, __u32 b) {
    KEEP(ctx); KEEP(a); KEEP(b); return (a == 99 && b == 77) ? RET : 0;
}
SEC("xdp") int layout_target(struct xdp_md *ctx) {
    results = one(ctx) + two(ctx, arg_a) + three(ctx, arg_a, arg_b);
    return RET;
}
char _license[] SEC("license") = "GPL";
`

// Mixed arities share one filter compilation and one ring map. The actual
// return (2) differs from both extra argument values (99 and 77).
func TestBpfFexitReturnLayout(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, h := range []struct {
		name, ctx, section, filter string
		retval                     uint32
		kind                       ebpf.ProgramType
	}{
		{"xdp", "xdp_md", "xdp", "eth where action == XDP_PASS", 2, ebpf.XDP},
		{"tc", "__sk_buff", "classifier", "eth where action == TC_ACT_OK", 0, ebpf.SchedCLS},
		{"cgroup", "__sk_buff", "cgroup_skb/egress", "ipv4 where action == SK_PASS", 1, ebpf.CGroupSKB},
	} {
		t.Run(h.name, func(t *testing.T) {
			source := strings.ReplaceAll(fexitLayoutSource, "struct xdp_md", "struct "+h.ctx)
			source = strings.ReplaceAll(source, `SEC("xdp")`, `SEC("`+h.section+`")`)
			source = strings.ReplaceAll(source, "#define RET 2", fmt.Sprintf("#define RET %d", h.retval))
			runFexitReturnLayout(t, source, h.filter, h.retval, h.kind, nil)
		})
	}
}

func runFexitReturnLayout(t *testing.T, source, expr string, retval uint32, kind ebpf.ProgramType, trigger func(*ebpf.Program) error) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, source))
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	prog := collection.Programs["layout_target"]
	var targets []attach.Target
	for i, name := range []string{"one", "two", "three"} {
		params, err := attach.GetFuncParams(prog, name)
		if err != nil || len(params) != i {
			t.Fatalf("%s fixture params: %+v, %v", name, params, err)
		}
		for n, p := range params {
			if p.Index != n+1 {
				t.Fatalf("%s parameter ABI: %+v", name, p)
			}
		}
		targets = append(targets, attach.Target{Program: prog, FuncName: name, Type: kind})
	}
	for _, expr := range []string{"", expr} {
		t.Run(fmt.Sprintf("filter=%s", expr), func(t *testing.T) {
			probe, err := LoadMultiExit(targets, expr, nil, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			if trigger != nil {
				if err := trigger(prog); err != nil {
					t.Fatal(err)
				}
			} else if _, err := prog.Run(&ebpf.RunOptions{Data: tcpPacket(0x99, 1234, 443)}); err != nil {
				t.Fatal(err)
			}
			records := 0
			for _, m := range probe.InnerMaps {
				r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				r.ReadBatch(func(raw []byte) {
					records++
					if len(raw) < metadataSize {
						t.Error("short record")
						return
					}
					if action := binary.NativeEndian.Uint32(raw[8:12]); action != retval {
						t.Errorf("action=%d, want return value %d", action, retval)
					}
				})
				_ = r.Close()
			}
			if records != 3 {
				t.Fatalf("captured %d returns, want 3", records)
			}
		})
	}
}

func TestFexitPrototypeRejectsAmbiguousLayouts(t *testing.T) {
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := btf.FuncParam{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md"}}}
	for _, parameter := range []btf.Type{&btf.Struct{Name: "pair", Size: 16}, &btf.Array{Type: integer, Nelems: 2}, &btf.Int{Size: 16}} {
		if _, err := fexitPrototypeOffset(&btf.FuncProto{Return: integer, Params: []btf.FuncParam{ctx, {Name: "extra", Type: parameter}}}); err == nil {
			t.Fatalf("accepted parameter %T", parameter)
		}
	}
	for _, result := range []btf.Type{&btf.Void{}, &btf.Pointer{Target: integer}, &btf.Int{Size: 8}, &btf.Int{Size: 1}} {
		if _, err := fexitPrototypeOffset(&btf.FuncProto{Return: result, Params: []btf.FuncParam{ctx}}); err == nil {
			t.Fatalf("accepted return %T", result)
		}
	}
	for n := 1; n <= 5; n++ {
		params := []btf.FuncParam{ctx}
		for len(params) < n {
			params = append(params, btf.FuncParam{Name: "n", Type: integer})
		}
		if offset, err := fexitPrototypeOffset(&btf.FuncProto{Return: integer, Params: params}); err != nil || offset != int16(n*8) {
			t.Fatalf("arity %d: offset %d, error %v", n, offset, err)
		}
	}
}

// Netfilter has no BPF_PROG_TEST_RUN packet path. Exercise its actual local-out
// hook in a private netns; one loopback datagram calls all three helpers once.
func TestBpfFexitReturnLayoutNetfilter(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := features.HaveProgramType(ebpf.Netfilter); errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("BPF_PROG_TYPE_NETFILTER not supported by this kernel (need 6.4+)")
	} else if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	isolated, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = isolated.Close() }()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restoring netns: %v", err)
		}
	}()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	destination, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(fexitLayoutSource, "struct xdp_md", "struct bpf_nf_ctx")
	source = strings.ReplaceAll(source, `SEC("xdp")`, `SEC("netfilter")`)
	source = strings.ReplaceAll(source, "#define RET 2", "#define RET 1")
	source = strings.ReplaceAll(source, "#include <linux/bpf.h>", "#include <linux/bpf.h>\nstruct nf_hook_state; struct sk_buff; struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; };")
	runFexitReturnLayout(t, source, "ipv4 where action == NF_ACCEPT", 1, ebpf.Netfilter, func(prog *ebpf.Program) error {
		// t.Run executes on its own goroutine, so enter the socket's netns
		// on this locked thread before creating its netfilter link.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		current, err := netns.Get()
		if err != nil {
			return err
		}
		defer func() { _ = current.Close() }()
		if err := netns.Set(isolated); err != nil {
			return err
		}
		defer func() {
			if err := netns.Set(current); err != nil {
				t.Errorf("restoring trigger netns: %v", err)
			}
		}()
		hook, err := link.AttachNetfilter(link.NetfilterOptions{Program: prog, ProtocolFamily: link.NetfilterProtoIPv4, Hook: link.NetfilterInetLocalOut})
		if err != nil {
			return err
		}
		defer func() { _ = hook.Close() }()
		return unix.Sendto(fd, []byte("fexit-return-layout"), 0, destination)
	})
}

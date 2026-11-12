package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/bpf-ninja/internal/follow"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// followFixture is one generation of a datapath: the packet's first byte
// selects a policy in pols. Injection adds the lookup hook rec_pols. The
// second generation's policy has no port member.
func followFixture(generation int) string {
	port := "__u16 port; __u16 pad;"
	if generation == 2 {
		port = "__u32 flags;"
	}
	return fmt.Sprintf(`
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
struct pol_key { __u32 policy_index; };
struct pol { __u32 pol_rc; %s };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct pol_key);
    __type(value, struct pol);
} pols SEC(".maps");
SEC("xdp")
int follow_target(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (data + 1 > end) return XDP_ABORTED;
    struct pol_key key = { .policy_index = *(__u8 *)data };
    struct pol *p = bpf_map_lookup_elem(&pols, &key);
    if (p && p->pol_rc == 0) return XDP_DROP;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
`, port)
}

// loadFollowGeneration injects and loads one generation with policies 1..3
// and returns the program, its ID and a function that drops the loader's
// references. BPF_NINJA_FOLLOW_OBJECT_<N> names a prebuilt object for a VM
// without clang.
func loadFollowGeneration(t *testing.T, generation int) (*ebpf.Program, uint32, func()) {
	t.Helper()
	obj := os.Getenv(fmt.Sprintf("BPF_NINJA_FOLLOW_OBJECT_%d", generation))
	if obj == "" {
		obj = testutil.CompileBPFSource(t, followFixture(generation))
	}
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inject.TransformLookup(elf, inject.LookupRequest{
		ELFSHA256: fmt.Sprintf("%x", sha256.Sum256(elf)), ProgramName: "follow_target", Auto: true,
		HookName: "rec", Stack: inject.StackAudit{LowestOffset: -64},
	})
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		t.Fatalf("loading generation %d: %v", generation, err)
	}
	t.Cleanup(coll.Close)
	for i := uint32(1); i <= 3; i++ {
		if err := coll.Maps["pols"].Put(i, [2]uint32{i, 1000 + i}); err != nil {
			t.Fatal(err)
		}
	}
	prog := coll.Programs["follow_target"]
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return prog, uint32(id), coll.Close
}

// liveCapture is a capture running in this process whose stderr the test
// reads as it is written.
type liveCapture struct {
	t       *testing.T
	lines   chan string
	all     strings.Builder
	done    chan error
	restore func()
}

func startCapture(t *testing.T, argv ...string) *liveCapture {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	var once sync.Once
	c := &liveCapture{t: t, lines: make(chan string, 256), done: make(chan error, 1)}
	c.restore = func() { once.Do(func() { os.Stderr = prev; _ = w.Close() }) }
	t.Cleanup(c.restore)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		_, _ = io.Copy(io.Discard, r)
		close(c.lines)
	}()
	go func() {
		c.done <- newRootCommand().Run(context.Background(), append([]string{"bpf-ninja"}, argv...))
	}()
	return c
}

// waitFor reads stderr until a line contains want.
func (c *liveCapture) waitFor(want string) {
	c.t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case line, ok := <-c.lines:
			if !ok {
				c.t.Fatalf("the capture ended before %q:\n%s", want, c.all.String())
			}
			c.all.WriteString(line + "\n")
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			c.t.Fatalf("no %q within 20s:\n%s", want, c.all.String())
		}
	}
}

// finish waits for the capture to return and gives all of its stderr.
func (c *liveCapture) finish() string {
	c.t.Helper()
	select {
	case err := <-c.done:
		if err != nil {
			c.t.Errorf("capture: %v", err)
		}
	case <-time.After(20 * time.Second):
		c.t.Fatalf("the capture did not end:\n%s", c.all.String())
	}
	c.restore()
	for line := range c.lines {
		c.all.WriteString(line + "\n")
	}
	return c.all.String()
}

// sendPolicies test-runs prog once per policy index.
func sendPolicies(t *testing.T, prog *ebpf.Program, indexes ...byte) {
	t.Helper()
	for _, idx := range indexes {
		data := make([]byte, 64)
		data[0] = idx
		if _, err := prog.Run(&ebpf.RunOptions{Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}

// epbInterfaces returns the interface ID of every packet block in a
// little-endian pcapng file.
func epbInterfaces(t *testing.T, path string) []uint32 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint32
	for off := 0; off+12 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		if n < 12 || off+n > len(b) {
			t.Fatalf("pcapng block at %d has length %d", off, n)
		}
		if binary.LittleEndian.Uint32(b[off:]) == 6 {
			out = append(out, binary.LittleEndian.Uint32(b[off+8:]))
		}
		off += n
	}
	return out
}

func tracingLinksForProgram(t *testing.T, id uint32) int {
	t.Helper()
	it := new(link.Iterator)
	defer it.Close()
	n := 0
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			t.Fatal(err)
		}
		if tr := info.Tracing(); info.Type == link.TracingType && tr != nil && tr.TargetObjectId == id {
			n++
		}
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestBpfFollowPollCLI captures at generation 1's hook and loads
// generation 2 while the capture runs. By default the capture finds the
// new program, reports the late attach as a gap and records its packets on
// the same interface. With --no-follow it stays on generation 1.
func TestBpfFollowPollCLI(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, follow := range []bool{true, false} {
		t.Run(fmt.Sprintf("follow=%v", follow), func(t *testing.T) {
			gen1, id1, drop1 := loadFollowGeneration(t, 1)
			out := filepath.Join(t.TempDir(), "follow.pcapng")
			argv := []string{"-p", fmt.Sprint(id1), "--func", "rec_pols", "-w", out, "-c", "6", "--no-cpu-affinity", "-v"}
			if !follow {
				argv = append(argv, "--no-follow")
			}
			c := startCapture(t, argv...)
			c.waitFor("capturing (")
			sendPolicies(t, gen1, 1, 2, 3)
			gen2, id2, _ := loadFollowGeneration(t, 1)
			if follow {
				c.waitFor(fmt.Sprintf("FOLLOW GAP: prog=%d func=rec_pols reason=late unobserved_ms=", id2))
				drop1()
				if n := tracingLinksForProgram(t, id1); n == 0 {
					t.Fatalf("generation 1 (id=%d) has no observer link", id1)
				}
				sendPolicies(t, gen2, 1, 2, 3)
			} else {
				time.Sleep(10 * followPollInterval)
				sendPolicies(t, gen2, 1, 2, 3)
				sendPolicies(t, gen1, 1, 2, 3)
			}
			stderr := c.finish()
			status := ""
			for _, line := range strings.Split(stderr, "\n") {
				if strings.HasPrefix(line, "capture status=") {
					status = line
				}
			}
			ifaces := epbInterfaces(t, out)
			if len(ifaces) != 6 {
				t.Fatalf("%d packets in the file, want 6\n%s", len(ifaces), stderr)
			}
			for _, i := range ifaces {
				if i != ifaces[0] {
					t.Fatalf("packets on interfaces %v, want one interface", ifaces)
				}
			}
			if follow {
				if !strings.HasPrefix(status, "capture status=incomplete ") ||
					!strings.Contains(status, " follow_attached=1 follow_held=0 follow_gaps=1 follow_gap_ms=") {
					t.Fatalf("status %q\n%s", status, stderr)
				}
				return
			}
			if !strings.HasPrefix(status, "capture status=complete ") || strings.Contains(stderr, "FOLLOW") || strings.Contains(stderr, "follow_") {
				t.Fatalf("status %q\n%s", status, stderr)
			}
		})
	}
}

// TestBpfFollowGapCLI loads a second generation whose policy lacks the
// member the capture's --arg-filter names. The capture cannot observe it:
// it reports the gap, ends incomplete, and keeps capturing generation 1.
func TestBpfFollowGapCLI(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	gen1, id1, _ := loadFollowGeneration(t, 1)
	out := filepath.Join(t.TempDir(), "gap.pcapng")
	c := startCapture(t, "-p", fmt.Sprint(id1), "--func", "rec_pols", "--arg-filter", "value->port>=1002", "-w", out, "-c", "2", "--no-cpu-affinity")
	c.waitFor("capturing (")
	gen2, id2, _ := loadFollowGeneration(t, 2)
	c.waitFor(fmt.Sprintf("FOLLOW GAP: prog=%d func=rec_pols reason=filter_unresolved unobserved_ms=", id2))
	sendPolicies(t, gen2, 1, 2, 3)
	sendPolicies(t, gen1, 1, 2, 3)
	stderr := c.finish()
	if n := len(epbInterfaces(t, out)); n != 2 {
		t.Fatalf("%d packets in the file, want 2\n%s", n, stderr)
	}
	if !strings.Contains(stderr, "capture status=incomplete ") || !strings.Contains(stderr, " follow_attached=0 follow_held=0 follow_gaps=1 ") {
		t.Fatal(stderr)
	}
}

// TestBpfFollowHeldCLI plays inject-run with a follow server in this
// process: it loads generation 2 and announces it while the capture runs.
// The capture attaches before the announcement returns, so the packets
// sent right after it are all captured, the attach counts as held and the
// capture ends complete.
func TestBpfFollowHeldCLI(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	server, err := follow.Listen(follow.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	gen1, id1, _ := loadFollowGeneration(t, 1)
	out := filepath.Join(t.TempDir(), "held.pcapng")
	c := startCapture(t, "-p", fmt.Sprint(id1), "--func", "rec_pols", "-w", out, "-c", "6", "--no-cpu-affinity", "-v")
	c.waitFor("subscribed to 1 inject-run process(es)")
	c.waitFor("capturing (")
	sendPolicies(t, gen1, 1, 2, 3)
	gen2, id2, _ := loadFollowGeneration(t, 1)
	if notified, held := server.Announce(id2, []string{"rec_pols"}); notified != 1 || held != 1 {
		t.Fatalf("announce: notified %d, held %d; want 1, 1", notified, held)
	}
	sendPolicies(t, gen2, 1, 2, 3)
	stderr := c.finish()
	if n := len(epbInterfaces(t, out)); n != 6 {
		t.Fatalf("%d packets in the file, want 6\n%s", n, stderr)
	}
	if !strings.Contains(stderr, "capture status=complete ") || !strings.Contains(stderr, " follow_attached=1 follow_held=1 follow_gaps=0 ") ||
		strings.Contains(stderr, "FOLLOW GAP") {
		t.Fatal(stderr)
	}
}

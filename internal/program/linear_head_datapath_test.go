package program

// Real-datapath confirmation of the linear-head clamp in the skb
// prologues: on modern kernels (5.19+) tcp_sendmsg places the payload
// entirely in page frags, so every bulk-TCP skb a cgroup-skb egress
// program sees is non-linear (skb->data_len > 0). Before the clamp the
// capture window ended at data + skb->len and the copied "payload"
// bytes came from unrelated kernel memory past the linear head; with
// the clamp the window ends at data + (len - data_len), so those
// records carry the L3/L4 headers and nothing else.
//
// The test sends a known 0xA5 byte pattern over loopback TCP inside a
// scratch cgroup with a pass-all cgroup-skb egress program attached and
// captures with a dport filter. Assertions:
//   (1) at least one record's IP total length exceeds its caplen
//       while caplen is below the snaplen limit, proving the window
//       was cut by the head clamp and not by snaplen, i.e. a
//       non-linear skb was actually exercised (guard against the test
//       silently passing on a linear-only path), and
//   (2) every captured byte after the TCP header equals the pattern.
// On the unclamped code (2) fails with overwhelming probability: the
// bytes past the head are whatever the kernel heap held.
//
// Root + cgroup v2 required; skipped otherwise. Run via make test-bpf
// or: sudo -E go test ./internal/program -run TestLinearHeadClamp -v

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

const cgroupSKBEgressPassSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("cgroup_skb/egress")
int cgroup_skb_egress_pass_test(struct __sk_buff *skb) { return 1; }
char _license[] SEC("license") = "GPL";
`

// moveSelfToCgroup writes the test process into path's cgroup.procs and
// returns a restore function that moves it back where it came from.
func moveSelfToCgroup(t *testing.T, path string) func() {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("reading /proc/self/cgroup: %v", err)
	}
	// "0::/some/path" on cgroup v2.
	orig := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0::"))
	pid := []byte(fmt.Sprintf("%d", os.Getpid()))
	if err := os.WriteFile(path+"/cgroup.procs", pid, 0); err != nil {
		t.Fatalf("moving self into %s: %v", path, err)
	}
	return func() {
		_ = os.WriteFile("/sys/fs/cgroup"+orig+"/cgroup.procs", pid, 0)
	}
}

func TestLinearHeadClampAtCgroupSKB(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	cgPath := fmt.Sprintf("/sys/fs/cgroup/bpfninja-linear-%d", os.Getpid())
	if err := os.Mkdir(cgPath, 0o755); err != nil {
		t.Skipf("cgroup v2 root not writable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgPath) })

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, cgroupSKBEgressPassSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	var objs struct {
		Prog *ebpf.Program `ebpf:"cgroup_skb_egress_pass_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading cgroup-skb egress program: %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgPath, Attach: ebpf.AttachCGroupInetEgress, Program: objs.Prog,
	})
	if err != nil {
		t.Fatalf("attaching to cgroup: %v", err)
	}
	t.Cleanup(func() { _ = lnk.Close() })

	// TCP server on loopback; the observer filter keys on its port so
	// only the client-to-server data direction is captured.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	probe := loadProbeOrFail(t, objs.Prog, "cgroup_skb_egress_pass_test",
		fmt.Sprintf("ipv4/tcp[dport==%d]", port), false, true)
	_ = probe

	// Bulk transfer with a fixed pattern. 256 KiB guarantees GSO-sized
	// non-linear skbs on lo (TSO is on by default there).
	const pattern = 0xA5
	payload := make([]byte, 256<<10)
	for i := range payload {
		payload[i] = pattern
	}
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64<<10)
		for {
			if _, err := conn.Read(buf); err != nil {
				done <- nil
				return
			}
		}
	}()

	restore := moveSelfToCgroup(t, cgPath)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		restore()
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		restore()
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()
	restore()
	<-done

	// Drain and check every captured record.
	innerSize := int(shardRingbufSize(RingbufSize, runtime.NumCPU()))
	readers := make([]*fastrb.Reader, len(probe.InnerMaps))
	for i, m := range probe.InnerMaps {
		rd, err := fastrb.New(m.FD(), innerSize)
		if err != nil {
			t.Fatalf("fastrb on shard %d: %v", i, err)
		}
		readers[i] = rd
	}
	defer func() {
		for _, rd := range readers {
			_ = rd.Close()
		}
	}()

	var records, nonLinear, badBytes int
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, rd := range readers {
			rd.ReadBatch(func(rec []byte) {
				// The ringbuf slot is fixed-size (metadata + snaplen, a
				// verifier constraint); the valid packet length is the
				// caplen field at metadata offset 14.
				if len(rec) < metadataSize {
					return
				}
				caplen := int(binary.LittleEndian.Uint16(rec[14:16]))
				if caplen < 20 || metadataSize+caplen > len(rec) {
					return
				}
				pkt := rec[metadataSize : metadataSize+caplen] // raw IP, L3 start
				records++
				ihl := int(pkt[0]&0x0f) * 4
				totLen := int(binary.BigEndian.Uint16(pkt[2:4]))
				// caplen == DefaultCapLen would mean the snaplen limit
				// cut the record, which a fully linear GSO packet also
				// produces; only a window shorter than both the packet
				// and the snaplen proves the head clamp fired.
				if totLen > caplen && caplen < DefaultCapLen {
					nonLinear++
				}
				if len(pkt) < ihl+20 {
					return
				}
				doff := int(pkt[ihl+12]>>4) * 4
				for _, b := range pkt[min(ihl+doff, len(pkt)):] {
					if b != pattern {
						badBytes++
					}
				}
			})
		}
		if records > 0 && time.Now().After(deadline.Add(-1500*time.Millisecond)) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if records == 0 {
		t.Fatal("no packets captured; cgroup egress path not exercised")
	}
	if nonLinear == 0 {
		t.Fatal("no record with IP total length beyond the capture window; the non-linear skb case was not exercised")
	}
	if badBytes != 0 {
		t.Fatalf("%d captured payload bytes differ from the sent pattern across %d records; the capture window read past the linear head", badBytes, records)
	}
	t.Logf("records=%d nonLinear=%d (all post-header bytes match the pattern)", records, nonLinear)
}

package program

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// The observer's optimized scratch copy must cover dynamic parser bounds,
// including options that are not explicitly queried by the predicate.
func TestBpfTracingVariableHeaderReadWindow(t *testing.T) {
	prog := loadDummyXDP(t)
	for _, tc := range []struct {
		name                  string
		ipOptions, tcpOptions int
	}{
		{"tcp", 0, 12}, {"ipv4", 12, 0}, {"both", 40, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := loadProbeOrFail(t, prog, xdpFuncName, "eth/ipv4/tcp[dport==443]", false, true)
			packet := tcpPacket(0x99, 1234, 443)[:54]
			packet[14] = 0x45 + byte(tc.ipOptions/4)
			packet[46] = byte(5+tc.tcpOptions/4) << 4
			packet = append(append(append([]byte(nil), packet[:34]...), bytes.Repeat([]byte{1}, tc.ipOptions)...), packet[34:]...)
			packet = append(packet, bytes.Repeat([]byte{1}, tc.tcpOptions)...)
			binary.BigEndian.PutUint16(packet[16:18], uint16(len(packet)-14))
			if _, err := prog.Run(&ebpf.RunOptions{Data: packet}); err != nil {
				t.Fatal(err)
			}
			if got := drainMarkers(t, probe, 1); got[0x99] != 1 {
				t.Fatalf("variable header packet lost: %v", got)
			}
		})
	}
}

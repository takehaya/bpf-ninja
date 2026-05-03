// Package capture reads packets from the per-CPU perf event buffer.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Packet represents a captured packet.
type Packet struct {
	Timestamp time.Time
	Data      []byte
	Action    uint32 // XDP action (fexit only)
	Mode      uint8  // 0=entry(fentry), 1=exit(fexit), 2=xdp-native
}

// XDP actions for display.
var XDPActionNames = map[uint32]string{
	0: "ABORTED",
	1: "DROP",
	2: "PASS",
	3: "TX",
	4: "REDIRECT",
}

// Reader reads captured packets from the perf buffer.
type Reader struct {
	reader *perf.Reader
}

// ErrClosed is returned when the reader has been closed.
var ErrClosed = errors.New("reader closed")

// NewReader creates a new packet reader from a perf event array map.
func NewReader(eventsMap *ebpf.Map, perCPUBuffer int) (*Reader, error) {
	reader, err := perf.NewReader(eventsMap, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	return &Reader{reader: reader}, nil
}

// bpf_xdp_output の perf event フォーマット:
//   RawSample = [metadata (8B)] [パケットデータ]
//   metadata:
//     u32 action  (offset 0)
//     u8  mode    (offset 4)
//     u8  _pad[3] (offset 5)
const MetadataSize = 8

// Read returns the next captured packet. Blocks until a packet is available.
func (r *Reader) Read() (Packet, error) {
	record, err := r.reader.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return Packet{}, ErrClosed
		}
		return Packet{}, fmt.Errorf("reading perf event: %w", err)
	}

	if record.LostSamples > 0 {
		return Packet{}, fmt.Errorf("lost %d samples", record.LostSamples)
	}

	pkt, err := ParseRawSample(record.RawSample)
	if err != nil {
		return Packet{}, err
	}
	pkt.Timestamp = time.Now()
	return pkt, nil
}

// ParseRawSample は perf event の RawSample をパースする。
func ParseRawSample(raw []byte) (Packet, error) {
	if len(raw) < MetadataSize {
		return Packet{}, fmt.Errorf("sample too short: %d bytes", len(raw))
	}

	return Packet{
		Action: binary.NativeEndian.Uint32(raw[0:4]),
		Mode:   raw[4],
		Data:   raw[MetadataSize:],
	}, nil
}

// Close closes the reader.
func (r *Reader) Close() error {
	return r.reader.Close()
}

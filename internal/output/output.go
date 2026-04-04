// Package output writes captured packets in pcap format to a file or stdout.
package output

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// Writer writes captured packets in pcapng format.
type Writer struct {
	pcapWriter *pcapgo.NgWriter
	file       *os.File       // non-nil only when writing to a file (not stdout)
	actionToID map[uint32]int // XDP action → pcapng interface index (exit mode only)
}

// NewWriter creates a pcapng writer. If path is empty, writes to stdout.
// In exit mode, creates one pcapng interface per XDP action so that
// Wireshark displays the action as the interface name.
func NewWriter(path string, mode string) (*Writer, error) {
	var dest io.Writer
	w := &Writer{}

	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating pcap file: %w", err)
		}
		w.file = f
		dest = f
	} else {
		dest = os.Stdout
	}

	var err error
	if mode == "exit" {
		err = w.initExitMode(dest)
	} else {
		w.pcapWriter, err = pcapgo.NewNgWriter(dest, layers.LinkTypeEthernet)
	}
	if err != nil {
		if w.file != nil {
			if cerr := w.file.Close(); cerr != nil {
				err = fmt.Errorf("%w (also failed to close file: %v)", err, cerr)
			}
		}
		return nil, fmt.Errorf("creating pcap writer: %w", err)
	}

	return w, nil
}

// initExitMode creates one pcapng interface per XDP action (ABORTED..REDIRECT).
func (w *Writer) initExitMode(dest io.Writer) error {
	actions := []struct {
		id   uint32
		name string
	}{
		{0, "xdp:ABORTED"},
		{1, "xdp:DROP"},
		{2, "xdp:PASS"},
		{3, "xdp:TX"},
		{4, "xdp:REDIRECT"},
	}

	first := pcapgo.NgInterface{
		Name:                actions[0].name,
		LinkType:            layers.LinkTypeEthernet,
		TimestampResolution: 9,
		SnapLength:          0,
		OS:                  runtime.GOOS,
	}
	pw, err := pcapgo.NewNgWriterInterface(dest, first, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return err
	}

	w.actionToID = map[uint32]int{actions[0].id: 0}
	for _, a := range actions[1:] {
		id, err := pw.AddInterface(pcapgo.NgInterface{
			Name:                a.name,
			LinkType:            layers.LinkTypeEthernet,
			TimestampResolution: 9,
			SnapLength:          0,
			OS:                  runtime.GOOS,
		})
		if err != nil {
			return err
		}
		w.actionToID[a.id] = id
	}

	w.pcapWriter = pw
	return nil
}

// Write outputs a captured packet.
func (w *Writer) Write(pkt capture.Packet) error {
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}
	if w.actionToID != nil {
		if id, ok := w.actionToID[pkt.Action]; ok {
			ci.InterfaceIndex = id
		}
		// unknown action falls back to interface 0
	}
	if err := w.pcapWriter.WritePacket(ci, pkt.Data); err != nil {
		return fmt.Errorf("writing pcap packet: %w", err)
	}
	return w.pcapWriter.Flush()
}

// Close flushes and closes resources.
func (w *Writer) Close() error {
	if err := w.pcapWriter.Flush(); err != nil {
		return err
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Package output writes captured packets in pcap format to a file or stdout.
package output

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// fileBufSize is the outer bufio.Writer capacity sitting between the
// pcapng writer and an underlying *os.File. pcapgo.NgWriter wraps its
// destination in a 4 KiB bufio internally, so without this outer
// stage every ~120 64-byte packets at 100 % match would still cost a
// write(2) syscall. 1 MiB lets the file path coalesce ~32 KiB worth
// of pcapng records per syscall, which is what tcpdump's libpcap
// _IOFBF stdio buffer effectively does.
const fileBufSize = 1 << 20

// stdoutFlushInterval bounds the time pcap consumers piped from
// xdp-ninja's stdout (e.g. `xdp-ninja ... | tcpdump -r -`) wait for
// the producer's bufio to fill before seeing data. 1 ms is well
// below interactive-feel thresholds and orders of magnitude smaller
// than per-packet write costs we removed.
const stdoutFlushInterval = time.Millisecond

// Writer writes captured packets in pcapng format.
type Writer struct {
	pcapWriter *pcapgo.NgWriter
	fastWriter *FastNgWriter // alternative to pcapWriter when env XDP_NINJA_FAST_PCAPNG=1
	bufWriter  *bufio.Writer // non-nil only when wrapping an *os.File
	file       *os.File      // non-nil only when writing to a file (not stdout)
	actionToID map[uint32]int

	flushStop chan struct{}
	flushDone chan struct{}
	flushMu   sync.Mutex
}

// NewWriter creates a pcapng writer. If path is empty, writes to stdout.
// In exit mode, creates one pcapng interface per XDP action so that
// Wireshark displays the action as the interface name.
func NewWriter(path string, isFexit bool) (*Writer, error) {
	var dest io.Writer
	w := &Writer{}

	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating pcap file: %w", err)
		}
		w.file = f
		w.bufWriter = bufio.NewWriterSize(f, fileBufSize)
		dest = w.bufWriter
	} else {
		dest = os.Stdout
	}

	var err error
	useFast := os.Getenv("XDP_NINJA_FAST_PCAPNG") == "1" && !isFexit
	if useFast {
		w.fastWriter, err = NewFastNgWriter(dest)
	} else if isFexit {
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

	if path == "" {
		w.startStdoutFlusher()
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
	if w.fastWriter != nil {
		return w.fastWriter.WritePacket(pkt.Timestamp, pkt.Data)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}
	if w.actionToID != nil {
		if id, ok := w.actionToID[pkt.Action]; ok {
			ci.InterfaceIndex = id
		}
	}
	if err := w.pcapWriter.WritePacket(ci, pkt.Data); err != nil {
		return fmt.Errorf("writing pcap packet: %w", err)
	}
	return nil
}

// WriteBatch writes multiple packets in one call.
func (w *Writer) WriteBatch(pkts []capture.Packet) error {
	if len(pkts) == 0 {
		return nil
	}
	if w.fastWriter != nil {
		for i := range pkts {
			p := &pkts[i]
			if err := w.fastWriter.WritePacket(p.Timestamp, p.Data); err != nil {
				return err
			}
		}
		return nil
	}
	var ci gopacket.CaptureInfo
	for i := range pkts {
		p := &pkts[i]
		ci.Timestamp = p.Timestamp
		ci.CaptureLength = len(p.Data)
		ci.Length = len(p.Data)
		ci.InterfaceIndex = 0
		if w.actionToID != nil {
			if id, ok := w.actionToID[p.Action]; ok {
				ci.InterfaceIndex = id
			}
		}
		if err := w.pcapWriter.WritePacket(ci, p.Data); err != nil {
			return fmt.Errorf("writing pcap packet: %w", err)
		}
	}
	return nil
}

// Flush forces both the pcapng inner buffer and (when present) the
// outer file bufio to drain to the underlying io.Writer / file.
// Safe to call concurrently with the stdout flusher goroutine.
func (w *Writer) Flush() error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if w.pcapWriter != nil {
		if err := w.pcapWriter.Flush(); err != nil {
			return err
		}
	}
	if w.bufWriter != nil {
		return w.bufWriter.Flush()
	}
	return nil
}

// Close flushes and closes resources.
func (w *Writer) Close() error {
	if w.flushStop != nil {
		close(w.flushStop)
		<-w.flushDone
		w.flushStop, w.flushDone = nil, nil
	}
	var errs []error
	if err := w.Flush(); err != nil {
		errs = append(errs, err)
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// startStdoutFlusher starts a background goroutine that calls Flush()
// every stdoutFlushInterval. Pipe consumers (e.g.
// `xdp-ninja ... | tcpdump -r -`) need to see data before the
// pcapgo bufio fills, otherwise they appear stuck.
func (w *Writer) startStdoutFlusher() {
	w.flushStop = make(chan struct{})
	w.flushDone = make(chan struct{})
	go func() {
		defer close(w.flushDone)
		ticker := time.NewTicker(stdoutFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-w.flushStop:
				return
			case <-ticker.C:
				_ = w.Flush()
			}
		}
	}()
}

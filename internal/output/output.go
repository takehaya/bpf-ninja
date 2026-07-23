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

	"github.com/takehaya/bpf-ninja/internal/capture"
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
// bpf-ninja's stdout (e.g. `bpf-ninja ... | tcpdump -r -`) wait for
// the producer's bufio to fill before seeing data. 1 ms is well
// below interactive-feel thresholds and orders of magnitude smaller
// than per-packet write costs we removed.
const stdoutFlushInterval = time.Millisecond

// ActionName pairs a verdict value with its pcap-ng interface name
// (e.g. "xdp:DROP"). Signed verdicts are stored as their uint32 bit
// pattern. The hook registry (internal/hook) is the source of these;
// output only renders them.
type ActionName struct {
	Value uint32
	Name  string
}

// Config selects the writer layout for one capture run. The zero value
// is the fentry Ethernet layout.
type Config struct {
	// IsFexit selects the exit-mode layout: one pcap-ng interface per
	// verdict (Actions) so Wireshark shows the verdict as the
	// interface name.
	IsFexit bool

	// LinkType is the pcap-ng link type; the zero value means Ethernet.
	LinkType layers.LinkType

	// Actions lists the exit-mode verdict interfaces in creation order.
	// Required when IsFexit is set (the shard merge fills it from its
	// input files when left empty).
	Actions []ActionName

	// HookName prefixes lazily-added interfaces for verdicts outside
	// Actions ("<HookName>:UNKNOWN(<n>)").
	HookName string
}

// linkTypeOrDefault resolves the zero value to Ethernet.
func (c Config) linkTypeOrDefault() layers.LinkType {
	if c.LinkType == 0 {
		return layers.LinkTypeEthernet
	}
	return c.LinkType
}

// Writer writes captured packets in pcapng format.
type Writer struct {
	cfg        Config
	pcapWriter *pcapgo.NgWriter
	fastWriter *FastNgWriter // default for non-fexit; env BPF_NINJA_FAST_PCAPNG=0 falls back to pcapWriter
	bufWriter  *bufio.Writer // non-nil only when wrapping an *os.File
	file       *os.File      // non-nil only when writing to a file (not stdout)
	actionToID map[uint32]int
	nameToID   map[string]int // exit mode: interface name → id, for the shard merge

	flushStop chan struct{}
	flushDone chan struct{}
	flushMu   sync.Mutex
}

// NewWriter creates a pcapng writer. If path is empty, writes to stdout.
// In exit mode (cfg.IsFexit), creates one pcapng interface per verdict in
// cfg.Actions so that Wireshark displays the verdict as the interface name.
func NewWriter(path string, cfg Config) (*Writer, error) {
	if cfg.IsFexit && len(cfg.Actions) == 0 {
		return nil, fmt.Errorf("exit-mode writer needs at least one action interface (Config.Actions)")
	}
	var dest io.Writer
	w := &Writer{cfg: cfg}

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
	// FastNgWriter is the default hot-path writer (~18% faster per packet
	// than gopacket's NgWriter, benchmarked); it emits packet-equivalent
	// pcap-ng (see TestFastNgWriterEquivalent). Exit mode still needs the
	// gopacket writer for its per-action multi-interface layout. Set
	// BPF_NINJA_FAST_PCAPNG=0 to force the gopacket writer.
	useFast := os.Getenv("BPF_NINJA_FAST_PCAPNG") != "0" && !cfg.IsFexit
	if useFast {
		w.fastWriter, err = NewFastNgWriter(dest, cfg.linkTypeOrDefault())
	} else if cfg.IsFexit {
		err = w.initExitMode(dest)
	} else {
		w.pcapWriter, err = pcapgo.NewNgWriter(dest, cfg.linkTypeOrDefault())
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

// initExitMode creates one pcapng interface per verdict in cfg.Actions
// (e.g. xdp:ABORTED..xdp:REDIRECT, or tc:TC_ACT_UNSPEC..tc:TC_ACT_TRAP).
func (w *Writer) initExitMode(dest io.Writer) error {
	actions := w.cfg.Actions
	pw, err := pcapgo.NewNgWriterInterface(dest, w.ngInterface(actions[0].Name), pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return err
	}

	w.actionToID = map[uint32]int{actions[0].Value: 0}
	w.nameToID = map[string]int{actions[0].Name: 0}
	for _, a := range actions[1:] {
		id, err := pw.AddInterface(w.ngInterface(a.Name))
		if err != nil {
			return err
		}
		w.actionToID[a.Value] = id
		w.nameToID[a.Name] = id
	}

	w.pcapWriter = pw
	return nil
}

// ngInterface builds the pcap-ng interface block shared by every
// exit-mode interface: same link type, only the name differs.
func (w *Writer) ngInterface(name string) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Name:                name,
		LinkType:            w.cfg.linkTypeOrDefault(),
		TimestampResolution: 9,
		SnapLength:          0,
		OS:                  runtime.GOOS,
	}
}

// ifaceIDForAction maps a verdict value to its pcap-ng interface id,
// lazily adding a "<hook>:UNKNOWN(<n>)" interface for verdicts outside
// the configured set (e.g. cgroup-skb egress congestion codes) so no
// packet is ever silently attributed to the wrong verdict. Falls back
// to interface 0 if the lazy add fails (a malformed file would be worse).
func (w *Writer) ifaceIDForAction(action uint32) int {
	if id, ok := w.actionToID[action]; ok {
		return id
	}
	prefix := w.cfg.HookName
	if prefix == "" {
		prefix = "verdict"
	}
	name := fmt.Sprintf("%s:UNKNOWN(%d)", prefix, int32(action))
	id, err := w.pcapWriter.AddInterface(w.ngInterface(name))
	if err != nil {
		id = 0
	}
	w.actionToID[action] = id
	w.nameToID[name] = id
	return id
}

// ifaceIDByName maps an interface name to this writer's interface id,
// lazily adding it when unseen. Used by the shard merge, which matches
// interfaces by name rather than by verdict value (shards may carry
// lazily-added unknown-verdict interfaces at arbitrary indices).
func (w *Writer) ifaceIDByName(name string) int {
	if id, ok := w.nameToID[name]; ok {
		return id
	}
	id, err := w.pcapWriter.AddInterface(w.ngInterface(name))
	if err != nil {
		id = 0
	}
	w.nameToID[name] = id
	return id
}

// Write outputs a captured packet.
func (w *Writer) Write(pkt capture.Packet) error {
	// Serialize with the periodic flusher goroutine (Flush also holds
	// flushMu) so writes and flushes don't race on the pcapng buffer or, for
	// the fast writer, the shared outer bufio. Uncontended for writers with
	// no flusher (plain -w, non-split), so the lock is ~free there.
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if w.fastWriter != nil {
		return w.fastWriter.WritePacket(pkt.Timestamp, pkt.Data)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}
	if w.actionToID != nil {
		ci.InterfaceIndex = w.ifaceIDForAction(pkt.Action)
	}
	if err := w.pcapWriter.WritePacket(ci, pkt.Data); err != nil {
		return fmt.Errorf("writing pcap packet: %w", err)
	}
	return nil
}

// writePacketIface writes one packet to an explicit pcap-ng interface
// id, bypassing the verdict→interface mapping. Only the shard merge
// uses this (it resolves interfaces by name via ifaceIDByName).
func (w *Writer) writePacketIface(ts time.Time, data []byte, ifaceID int) error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if w.fastWriter != nil {
		return w.fastWriter.WritePacket(ts, data)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      ts,
		CaptureLength:  len(data),
		Length:         len(data),
		InterfaceIndex: ifaceID,
	}
	if err := w.pcapWriter.WritePacket(ci, data); err != nil {
		return fmt.Errorf("writing pcap packet: %w", err)
	}
	return nil
}

// WriteBatch writes multiple packets in one call.
func (w *Writer) WriteBatch(pkts []capture.Packet) error {
	if len(pkts) == 0 {
		return nil
	}
	// One lock for the whole batch (see Write): mutual exclusion with the
	// periodic flusher; uncontended for writers with no flusher.
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
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
			ci.InterfaceIndex = w.ifaceIDForAction(p.Action)
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
// `bpf-ninja ... | tcpdump -r -`) need to see data before the
// pcapgo bufio fills, otherwise they appear stuck.
func (w *Writer) startStdoutFlusher() {
	w.startFlusher(stdoutFlushInterval)
}

// EnablePeriodicFlush starts a background flusher on a file writer so its
// on-disk pcap-ng stays current within interval — a reader can copy or tail
// the file mid-capture and, once writes to it stop, it is complete after at
// most one interval. No-op if a flusher is already running (stdout writers
// start one in NewWriter).
func (w *Writer) EnablePeriodicFlush(interval time.Duration) {
	if w.flushStop != nil {
		return
	}
	w.startFlusher(interval)
}

// startFlusher runs a ticker goroutine that Flush()es every interval until
// Close stops it. Flush holds flushMu, so it never races the writes.
func (w *Writer) startFlusher(interval time.Duration) {
	w.flushStop = make(chan struct{})
	w.flushDone = make(chan struct{})
	go func() {
		defer close(w.flushDone)
		ticker := time.NewTicker(interval)
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

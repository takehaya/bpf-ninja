// Hand-rolled pcap-ng writer optimised for the high-rate capture
// hot path. gopacket/pcapgo's NgWriter performs interface dispatch
// + 5 separate Write() calls per packet through a 4 KiB internal
// bufio, plus byte-order conversion via reflection-friendly helpers
// — fine at low rate, but at multi-CPU sharded ringbuf rates
// (>1 Mpps per shard) it becomes the dominant userspace cost
// (measured: 60× slowdown vs --null-output).
//
// FastNgWriter cuts that to one direct byte-slice write per packet:
// the EPB header is built in a stack-resident 28-byte buffer with
// inline binary.LittleEndian.PutUint32 calls (compiler-intrinsic on
// amd64), and packet data + 4-byte trailer are written through the
// same outer bufio.Writer that the rest of output.Writer uses.
//
// On-wire format is a valid pcap-ng — SHB (Section Header Block) +
// single IDB (Interface Description Block) + sequence of EPBs (Enhanced
// Packet Blocks); tcpdump -r and Wireshark consume it without
// modification. It is not byte-identical to gopacket's NgWriter:
// gopacket writes optional descriptive strings (shb_os / shb_hardware /
// shb_userappl in the SHB, if_name in the IDB) that carry no packet data
// and that this writer omits. Every EPB — timestamps, caplen, packet
// bytes — matches, so both files read back to the same packets
// (TestFastNgWriter* in output pin this).

package output

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket/layers"
)

// pcap-ng block types (RFC draft, IETF opsawg-pcapng).
const (
	blkSHB = 0x0A0D0D0A
	blkIDB = 0x00000001
	blkEPB = 0x00000006

	shbByteOrderMagic = 0x1A2B3C4D
	shbVersionMajor   = 1
	shbVersionMinor   = 0

	// Timestamp resolution: nanoseconds, encoded in IDB option
	// if_tsresol = 9 (i.e. 10^-9). Default is 10^-6 (microseconds);
	// we emit the option to match gopacket's default behaviour.
	idbOptIfTsresol = 9 // option code
	idbTsresolNs    = 9 // 10^-9 = ns

	// if_name (IDB option 2) and epb_packetid (EPB option 5): the
	// latter is the pcap-ng way to say "this EPB and that EPB are the
	// same packet seen at different interfaces", which is exactly what
	// an entry record and an exit record of one invocation are.
	idbOptIfName   = 2
	epbOptPacketID = 5
	optEndOfOpt    = 0
)

// FastNgWriter writes pcap-ng to an io.Writer, bypassing gopacket
// for the EPB hot path. Caller is responsible for thread-safety
// (use a single writer per goroutine, or wrap in a mutex).
type FastNgWriter struct {
	w        io.Writer
	linkType uint16
	nIfaces  int
	// Pre-allocated 32-byte scratch slice for EPB header + trailer.
	// 28 bytes header + 4 bytes trailer fit; padding bytes (0-3) are
	// emitted via a separate constant zero-buffer.
	hdr [32]byte
}

// NewFastNgWriter creates a writer with SHB + a single IDB written.
// Caller writes packets via WritePacket. The IDB has timestamp
// resolution = nanoseconds (matches gopacket pcapgo default of
// TimestampResolution: 9).
func NewFastNgWriter(w io.Writer, linkType layers.LinkType) (*FastNgWriter, error) {
	fw := &FastNgWriter{w: w, linkType: uint16(linkType)}
	if err := fw.writeSHB(); err != nil {
		return nil, err
	}
	if err := fw.writeIDB(uint16(linkType)); err != nil {
		return nil, err
	}
	fw.nIfaces = 1
	return fw, nil
}

// NewFastNgWriterIfaces creates a writer with SHB + one named IDB per
// entry of names (interface ids 0..len-1, in order), all with the same
// link type. Packets are written with WritePacketID so each EPB names
// its interface and carries an epb_packetid.
func NewFastNgWriterIfaces(w io.Writer, linkType layers.LinkType, names []string) (*FastNgWriter, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("fast pcap-ng writer: need at least one interface name")
	}
	fw := &FastNgWriter{w: w, linkType: uint16(linkType)}
	if err := fw.writeSHB(); err != nil {
		return nil, err
	}
	for _, n := range names {
		if _, err := fw.AddInterface(n); err != nil {
			return nil, err
		}
	}
	return fw, nil
}

// AddInterface appends a named IDB and returns its interface id. pcap-ng
// allows IDBs anywhere in a section, so this is valid mid-stream (used
// for lazily-added unknown-verdict interfaces).
func (fw *FastNgWriter) AddInterface(name string) (int, error) {
	if err := fw.writeIDBNamed(fw.linkType, name); err != nil {
		return 0, err
	}
	id := fw.nIfaces
	fw.nIfaces++
	return id, nil
}

// writeIDBNamed is writeIDB plus an if_name option (code 2, value
// padded to 4 bytes) in front of if_tsresol.
func (fw *FastNgWriter) writeIDBNamed(linkType uint16, name string) error {
	namePad := (len(name) + 3) &^ 3
	total := 16 + 4 + namePad + 8 + 4 + 4
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:4], blkIDB)
	binary.LittleEndian.PutUint32(b[4:8], uint32(total))
	binary.LittleEndian.PutUint16(b[8:10], linkType)
	binary.LittleEndian.PutUint16(b[10:12], 0) // reserved
	binary.LittleEndian.PutUint32(b[12:16], 0) // snaplen = unlimited
	o := 16
	binary.LittleEndian.PutUint16(b[o:o+2], idbOptIfName)
	binary.LittleEndian.PutUint16(b[o+2:o+4], uint16(len(name)))
	copy(b[o+4:], name)
	o += 4 + namePad
	binary.LittleEndian.PutUint16(b[o:o+2], idbOptIfTsresol)
	binary.LittleEndian.PutUint16(b[o+2:o+4], 1)
	b[o+4] = idbTsresolNs
	o += 8
	binary.LittleEndian.PutUint16(b[o:o+2], optEndOfOpt)
	binary.LittleEndian.PutUint16(b[o+2:o+4], 0)
	o += 4
	binary.LittleEndian.PutUint32(b[o:o+4], uint32(total))
	_, err := fw.w.Write(b)
	return err
}

// writeSHB emits a Section Header Block with no options.
//
//	Block Type:        0x0A0D0D0A   (4 B)
//	Block Total Length: 28           (4 B)
//	Byte-Order Magic:   0x1A2B3C4D   (4 B)
//	Major Version:      1            (2 B)
//	Minor Version:      0            (2 B)
//	Section Length:     -1 (= unknown) (8 B, signed)
//	Block Total Length: 28           (4 B, repeated)
//	Total: 28 bytes
func (fw *FastNgWriter) writeSHB() error {
	var b [28]byte
	binary.LittleEndian.PutUint32(b[0:4], blkSHB)
	binary.LittleEndian.PutUint32(b[4:8], 28)
	binary.LittleEndian.PutUint32(b[8:12], shbByteOrderMagic)
	binary.LittleEndian.PutUint16(b[12:14], shbVersionMajor)
	binary.LittleEndian.PutUint16(b[14:16], shbVersionMinor)
	// Section Length = -1 (8 bytes signed)
	binary.LittleEndian.PutUint64(b[16:24], 0xFFFFFFFFFFFFFFFF)
	binary.LittleEndian.PutUint32(b[24:28], 28)
	_, err := fw.w.Write(b[:])
	return err
}

// writeIDB emits an Interface Description Block with one option:
// if_tsresol = 9 (nanosecond timestamps).
//
//	Block Type:         0x00000001   (4 B)
//	Block Total Length: variable     (4 B)
//	LinkType:           value        (2 B)
//	Reserved:           0            (2 B)
//	SnapLen:            0 (= no limit) (4 B)
//	Options:
//	  opt_tsresol:
//	    code = 9, length = 1, value = 9, padding = 3 → 8 bytes
//	  opt_endofopt:
//	    code = 0, length = 0 → 4 bytes
//	Block Total Length: variable     (4 B, repeated)
//	Total: 16 + 8 + 4 + 4 = 32 bytes
func (fw *FastNgWriter) writeIDB(linkType uint16) error {
	var b [32]byte
	binary.LittleEndian.PutUint32(b[0:4], blkIDB)
	binary.LittleEndian.PutUint32(b[4:8], 32)
	binary.LittleEndian.PutUint16(b[8:10], linkType)
	binary.LittleEndian.PutUint16(b[10:12], 0) // reserved
	binary.LittleEndian.PutUint32(b[12:16], 0) // snaplen = unlimited
	// opt if_tsresol: code=9, length=1, value=9, padding 3
	binary.LittleEndian.PutUint16(b[16:18], idbOptIfTsresol)
	binary.LittleEndian.PutUint16(b[18:20], 1)
	b[20] = idbTsresolNs
	// b[21..23] zeroed by default
	// opt endofopt: code=0, length=0
	binary.LittleEndian.PutUint16(b[24:26], 0)
	binary.LittleEndian.PutUint16(b[26:28], 0)
	binary.LittleEndian.PutUint32(b[28:32], 32)
	_, err := fw.w.Write(b[:])
	return err
}

// epbZeroPad is shared trailing-padding bytes for EPB packet data
// alignment to 4-byte boundary. Up to 3 bytes are written from this
// slice depending on packet length.
var epbZeroPad = [3]byte{0, 0, 0}

// EPBSize returns the on-disk size of one Enhanced Packet Block for a
// packet of caplen bytes: 32 bytes of framing plus the data padded to a
// 4-byte boundary. Byte-cap accounting (--max-bytes*) uses this so its
// notion of "output bytes" matches what WritePacket emits.
func EPBSize(caplen int) int {
	return 32 + (caplen+3)&^3
}

// epbIDOptSize is the size of the options area WritePacketID appends:
// epb_packetid (4 B header + 8 B value) + opt_endofopt (4 B).
const epbIDOptSize = 16

// EPBSizeID is EPBSize for an EPB written by WritePacketID.
func EPBSizeID(caplen int) int {
	return EPBSize(caplen) + epbIDOptSize
}

// WritePacketID emits one Enhanced Packet Block on interface ifaceID
// with an epb_packetid option carrying packetID. Same framing as
// WritePacket plus 16 bytes of options between the padded data and the
// trailing block length.
func (fw *FastNgWriter) WritePacketID(ts time.Time, data []byte, ifaceID int, packetID uint64) error {
	caplen := uint32(len(data))
	totalLen := uint32(EPBSizeID(len(data)))
	pad := totalLen - 32 - epbIDOptSize - caplen

	tsNs := uint64(ts.UnixNano())
	binary.LittleEndian.PutUint32(fw.hdr[0:4], blkEPB)
	binary.LittleEndian.PutUint32(fw.hdr[4:8], totalLen)
	binary.LittleEndian.PutUint32(fw.hdr[8:12], uint32(ifaceID))
	binary.LittleEndian.PutUint32(fw.hdr[12:16], uint32(tsNs>>32))
	binary.LittleEndian.PutUint32(fw.hdr[16:20], uint32(tsNs))
	binary.LittleEndian.PutUint32(fw.hdr[20:24], caplen)
	binary.LittleEndian.PutUint32(fw.hdr[24:28], caplen)
	if _, err := fw.w.Write(fw.hdr[:28]); err != nil {
		return fmt.Errorf("EPB header: %w", err)
	}
	if caplen > 0 {
		if _, err := fw.w.Write(data); err != nil {
			return fmt.Errorf("EPB data: %w", err)
		}
		if pad > 0 {
			if _, err := fw.w.Write(epbZeroPad[:pad]); err != nil {
				return fmt.Errorf("EPB pad: %w", err)
			}
		}
	}
	// Options + trailer (20 bytes) reuse hdr[0..20].
	binary.LittleEndian.PutUint16(fw.hdr[0:2], epbOptPacketID)
	binary.LittleEndian.PutUint16(fw.hdr[2:4], 8)
	binary.LittleEndian.PutUint64(fw.hdr[4:12], packetID)
	binary.LittleEndian.PutUint16(fw.hdr[12:14], optEndOfOpt)
	binary.LittleEndian.PutUint16(fw.hdr[14:16], 0)
	binary.LittleEndian.PutUint32(fw.hdr[16:20], totalLen)
	if _, err := fw.w.Write(fw.hdr[:20]); err != nil {
		return fmt.Errorf("EPB options/trailer: %w", err)
	}
	return nil
}

// WritePacket emits one Enhanced Packet Block.
//
//	Block Type:                0x00000006  (4 B)
//	Block Total Length:        variable    (4 B)
//	Interface ID:              0           (4 B)
//	Timestamp High (upper 32 of u64 ns):  (4 B)
//	Timestamp Low  (lower 32 of u64 ns):  (4 B)
//	Captured Packet Length:    len(data)   (4 B)
//	Original Packet Length:    len(data)   (4 B)
//	Packet Data:               len(data) bytes, padded to 4 B
//	Block Total Length:        repeated    (4 B)
//
//	Total = 32 + len(data) + padding
//
// Single packet → 3 io.Writer.Write calls (header, data, trailer
// with padding). The outer bufio.Writer coalesces them.
func (fw *FastNgWriter) WritePacket(ts time.Time, data []byte) error {
	caplen := uint32(len(data))
	totalLen := uint32(EPBSize(len(data)))
	pad := totalLen - 32 - caplen

	tsNs := uint64(ts.UnixNano())

	// Build header (28 bytes) into hdr[0..28].
	binary.LittleEndian.PutUint32(fw.hdr[0:4], blkEPB)
	binary.LittleEndian.PutUint32(fw.hdr[4:8], totalLen)
	binary.LittleEndian.PutUint32(fw.hdr[8:12], 0) // interface ID = 0
	binary.LittleEndian.PutUint32(fw.hdr[12:16], uint32(tsNs>>32))
	binary.LittleEndian.PutUint32(fw.hdr[16:20], uint32(tsNs))
	binary.LittleEndian.PutUint32(fw.hdr[20:24], caplen)
	binary.LittleEndian.PutUint32(fw.hdr[24:28], caplen) // original length

	if _, err := fw.w.Write(fw.hdr[:28]); err != nil {
		return fmt.Errorf("EPB header: %w", err)
	}
	if caplen > 0 {
		if _, err := fw.w.Write(data); err != nil {
			return fmt.Errorf("EPB data: %w", err)
		}
		if pad > 0 {
			if _, err := fw.w.Write(epbZeroPad[:pad]); err != nil {
				return fmt.Errorf("EPB pad: %w", err)
			}
		}
	}
	// Trailer: repeat block_total_length.
	binary.LittleEndian.PutUint32(fw.hdr[28:32], totalLen)
	if _, err := fw.w.Write(fw.hdr[28:32]); err != nil {
		return fmt.Errorf("EPB trailer: %w", err)
	}
	return nil
}

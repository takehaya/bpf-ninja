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
)

// pcap-ng block types (RFC draft, IETF opsawg-pcapng).
const (
	blkSHB = 0x0A0D0D0A
	blkIDB = 0x00000001
	blkEPB = 0x00000006

	shbByteOrderMagic = 0x1A2B3C4D
	shbVersionMajor   = 1
	shbVersionMinor   = 0

	// LinkType: LINKTYPE_ETHERNET (1).
	linkTypeEthernet = 1

	// Timestamp resolution: nanoseconds, encoded in IDB option
	// if_tsresol = 9 (i.e. 10^-9). Default is 10^-6 (microseconds);
	// we emit the option to match gopacket's default behaviour.
	idbOptIfTsresol = 9 // option code
	idbTsresolNs    = 9 // 10^-9 = ns
)

// FastNgWriter writes pcap-ng to an io.Writer, bypassing gopacket
// for the EPB hot path. Caller is responsible for thread-safety
// (use a single writer per goroutine, or wrap in a mutex).
type FastNgWriter struct {
	w io.Writer
	// Pre-allocated 32-byte scratch slice for EPB header + trailer.
	// 28 bytes header + 4 bytes trailer fit; padding bytes (0-3) are
	// emitted via a separate constant zero-buffer.
	hdr [32]byte
}

// NewFastNgWriter creates a writer with SHB + a single IDB written.
// Caller writes packets via WritePacket. The IDB has timestamp
// resolution = nanoseconds (matches gopacket pcapgo default of
// TimestampResolution: 9).
func NewFastNgWriter(w io.Writer) (*FastNgWriter, error) {
	fw := &FastNgWriter{w: w}
	if err := fw.writeSHB(); err != nil {
		return nil, err
	}
	if err := fw.writeIDB(linkTypeEthernet); err != nil {
		return nil, err
	}
	return fw, nil
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
	pad := uint32(0)
	if r := caplen & 3; r != 0 {
		pad = 4 - r
	}
	totalLen := 32 + caplen + pad

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

package output

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

const epbOptComment = 1

// HookEPBSize is the on-disk size of an EPB that WriteHookPacket writes.
func HookEPBSize(caplen int, packetID bool, comment int) int {
	n := EPBSize(caplen)
	if packetID {
		n += 12
	}
	if comment > 0 {
		n += 4 + (comment+3)&^3
	}
	if packetID || comment > 0 {
		n += 4 // opt_endofopt
	}
	return n
}

// WriteHookPacket writes one EPB on ifaceID with an epb_packetid when
// packetID is nonzero and an opt_comment when comment is non-empty. With
// a packet id and no comment it writes exactly what WritePacketID writes.
func (fw *FastNgWriter) WriteHookPacket(ts time.Time, data []byte, ifaceID int, packetID uint64, comment []byte) error {
	if len(comment) == 0 && packetID != 0 {
		return fw.WritePacketID(ts, data, ifaceID, packetID)
	}
	if len(comment) > 65535 {
		return fmt.Errorf("record comment exceeds pcapng option length")
	}
	total := uint32(HookEPBSize(len(data), packetID != 0, len(comment)))
	tsNs := uint64(ts.UnixNano())
	b := fw.rec[:0]
	for _, v := range []uint32{blkEPB, total, uint32(ifaceID), uint32(tsNs >> 32), uint32(tsNs), uint32(len(data)), uint32(len(data))} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	b = append(append(b, data...), epbZeroPad[:(4-len(data)%4)%4]...)
	if packetID != 0 {
		b = binary.LittleEndian.AppendUint32(b, epbOptPacketID|8<<16)
		b = binary.LittleEndian.AppendUint64(b, packetID)
	}
	if len(comment) != 0 {
		b = binary.LittleEndian.AppendUint32(b, epbOptComment|uint32(len(comment))<<16)
		b = append(append(b, comment...), epbZeroPad[:(4-len(comment)%4)%4]...)
		b = binary.LittleEndian.AppendUint32(b, optEndOfOpt)
	}
	b = binary.LittleEndian.AppendUint32(b, total)
	fw.rec = b
	if _, err := fw.w.Write(b); err != nil {
		return fmt.Errorf("EPB: %w", err)
	}
	return nil
}

// recordComment renders a hook record's block with its site's layout into
// the writer's reusable buffer, so the hot path allocates nothing per packet.
func (w *Writer) recordComment(p *capture.Packet) ([]byte, error) {
	b := w.comment[:0]
	if w.cfg.RecordReturn {
		b = append(b, "return=0x"...)
		b = appendHex32(b, p.Action)
	}
	i := int(p.SiteID) - 1
	if i >= len(w.cfg.Records) || w.cfg.Records[i] == nil {
		if p.Record != nil {
			return nil, fmt.Errorf("site_id=%d records nothing but carries a record block", p.SiteID)
		}
		w.comment = b
		return b, nil
	}
	if p.Record == nil {
		return nil, fmt.Errorf("site_id=%d record has no record block", p.SiteID)
	}
	b, err := w.cfg.Records[i].AppendComment(b, p.Record)
	w.comment = b
	return b, err
}

// appendHex32 appends v as eight lowercase hex digits.
func appendHex32(b []byte, v uint32) []byte {
	const digits = "0123456789abcdef"
	for shift := 28; shift >= 0; shift -= 4 {
		b = append(b, digits[v>>uint(shift)&0xf])
	}
	return b
}

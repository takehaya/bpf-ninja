package output

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// epbPacketIDs walks a pcap-ng byte stream and returns the
// epb_packetid option (code 5) of every EPB, in order, checking that
// each block is EPBSizeID(caplen) bytes (what byte-cap accounting
// assumes). gopacket's reader drops EPB options, so the check is done
// on the raw blocks.
func epbPacketIDs(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var ids []uint64
	for off := 0; off+8 <= len(b); {
		typ := binary.LittleEndian.Uint32(b[off:])
		total := int(binary.LittleEndian.Uint32(b[off+4:]))
		if total < 12 || off+total > len(b) {
			t.Fatalf("bad block at %d: type=%#x total=%d", off, typ, total)
		}
		if typ == blkEPB {
			caplen := int(binary.LittleEndian.Uint32(b[off+20:]))
			if total != EPBSizeID(caplen) {
				t.Errorf("EPB at %d: total %d, want EPBSizeID(%d) = %d", off, total, caplen, EPBSizeID(caplen))
			}
			o := off + 28 + (caplen+3)&^3
			var id uint64
			for o+4 <= off+total-4 {
				code := binary.LittleEndian.Uint16(b[o:])
				l := int(binary.LittleEndian.Uint16(b[o+2:]))
				if code == optEndOfOpt {
					break
				}
				if code == epbOptPacketID && l == 8 {
					id = binary.LittleEndian.Uint64(b[o+4:])
				}
				o += 4 + (l+3)&^3
			}
			ids = append(ids, id)
		}
		off += total
	}
	return ids
}

// TestWriterMultiPoint pins the entry+exit layout: verdict interfaces
// first, "<hook>:entry" last, entry records (Mode 0) on the entry
// interface, exit records by verdict (unknown verdicts get a lazily
// added interface), and Packet.PacketID carried as epb_packetid on
// both so they pair.
func TestWriterMultiPoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mp.pcapng")
	w, err := NewWriter(path, Config{
		MultiPoint: true, // implies IsFexit
		HookName:   "xdp",
		Actions:    []ActionName{{Value: 1, Name: "xdp:DROP"}, {Value: 2, Name: "xdp:PASS"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(10, 0)
	pkts := []capture.Packet{
		{Timestamp: ts, Data: []byte{0xaa, 0xbb}, Mode: 0, PacketID: 0x1000},
		{Timestamp: ts.Add(time.Microsecond), Data: []byte{0xcc}, Mode: 1, Action: 1, PacketID: 0x1000},
		{Timestamp: ts.Add(2 * time.Microsecond), Data: []byte{0xdd}, Mode: 1, Action: 9, PacketID: 0x2000}, // unknown verdict → lazy iface
	}
	if err := w.Write(pkts[0]); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteBatch(pkts[1:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{2, 0, 3} {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if ci.InterfaceIndex != want || !bytes.Equal(data, pkts[i].Data) {
			t.Errorf("packet %d: iface=%d data=%x, want iface=%d data=%x", i, ci.InterfaceIndex, data, want, pkts[i].Data)
		}
	}
	// gopacket registers IDBs as it meets them, so interfaces are
	// checked after the packets have been read.
	wantNames := []string{"xdp:DROP", "xdp:PASS", "xdp:entry", "xdp:UNKNOWN(9)"}
	if n := r.NInterfaces(); n != len(wantNames) {
		t.Fatalf("NInterfaces = %d, want %d", n, len(wantNames))
	}
	for i, name := range wantNames {
		if intf, err := r.Interface(i); err != nil || intf.Name != name {
			t.Errorf("interface %d = %q, want %q", i, intf.Name, name)
		}
	}
	if got, want := epbPacketIDs(t, raw), []uint64{0x1000, 0x1000, 0x2000}; !slices.Equal(got, want) {
		t.Errorf("epb_packetid = %x, want %x", got, want)
	}
	if got, want := w.EPBSize(2), EPBSizeID(2); got != want {
		t.Errorf("EPBSize(2) = %d, want EPBSizeID = %d", got, want)
	}
}

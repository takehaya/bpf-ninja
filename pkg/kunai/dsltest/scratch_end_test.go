package dsltest

import (
	"encoding/binary"
	"testing"
)

func TestTCPOptionExactScratchEnd(t *testing.T) {
	r := New(t, "ipv6/tcp where tcp.options.MSS.value == 1460")
	p := BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, Exts: []IPv6Ext{{HdrExtLen: 53}}})[14:]
	p = p[:492]
	p[484] = 10 << 4
	p = append(p, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7, 4, 2, 2, 4, 5, 180)
	p[4], p[5] = byte((len(p)-40)>>8), byte(len(p)-40)
	p[488], p[489] = 0, 0
	pseudo := append([]byte(nil), p[8:40]...)
	pseudo = append(pseudo, 0, 0, 0, 40, 0, 0, 0, 6)
	pseudo = append(pseudo, p[472:]...)
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[488:490], ^uint16(sum))
	t.Logf("packet length %d", len(p))
	New(t, "ipv6/tcp").MustMatch(t, p, "bare TCP may end exactly at scratch boundary")
	q := append([]byte(nil), p[:464]...)
	q = append(q, p[472:]...)
	q[41] = 52
	q[4], q[5] = byte((len(q)-40)>>8), byte(len(q)-40)
	r.MustMatch(t, q, "shorter 504-byte control packet")
	r.MustMatch(t, p, "MSS options end exactly at byte 512")
	r.MustReject(t, p[:511], "last option byte missing")
	beyond := append(append([]byte(nil), p[:472]...), make([]byte, 8)...)
	beyond = append(beyond, p[472:]...)
	beyond[41] = 54
	r.MustReject(t, beyond, "TCP option region extends past scratch capacity")
}

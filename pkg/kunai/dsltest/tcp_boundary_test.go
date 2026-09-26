package dsltest

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func tcpWithRawOptions(t *testing.T, offset byte, options, payload []byte) []byte {
	t.Helper()
	o := Defaults()
	o.Payload = nil
	pkt := Build(t, o)
	const tcpStart = 14 + 20
	pkt = pkt[:tcpStart+20]
	pkt[tcpStart+12] = offset << 4
	pkt = append(pkt, options...)
	pkt = append(pkt, payload...)
	// Preserve wire lengths and checksums while deliberately overriding the
	// TCP data offset or option encoding under test.
	binary.BigEndian.PutUint16(pkt[16:18], uint16(len(pkt)-14))
	pkt[24], pkt[25] = 0, 0
	binary.BigEndian.PutUint16(pkt[24:26], rawChecksum(pkt[14:34]))
	pkt[tcpStart+16], pkt[tcpStart+17] = 0, 0
	pseudo := append([]byte(nil), pkt[26:34]...)
	pseudo = append(pseudo, 0, 6, byte((len(pkt)-tcpStart)>>8), byte(len(pkt)-tcpStart))
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], rawChecksum(append(pseudo, pkt[tcpStart:]...)))
	return pkt
}

func TestTCPOptionHeaderBoundary(t *testing.T) {
	mss := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460")
	mss.MustMatch(t, tcpWithRawOptions(t, 6, []byte{2, 4, 5, 180}, nil), "real MSS")
	mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{2, 4, 5, 179}, nil), "different MSS")
	mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{1, 1, 1, 1}, []byte{2, 4, 5, 180, 0}), "payload is not MSS")
	mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{1, 2, 4, 5}, []byte{180, 0}), "MSS crosses header end")
	mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{2, 4, 5}, nil), "truncated MSS")
	mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{0, 2, 4, 5}, []byte{180, 0}), "EOL ends options")
	for _, offset := range []byte{0, 4, 5} {
		mss.MustReject(t, tcpWithRawOptions(t, offset, nil, []byte{2, 4, 5, 180, 0}), "no option area")
	}
	for _, length := range []byte{0, 1, 3, 5} {
		mss.MustReject(t, tcpWithRawOptions(t, 6, []byte{2, length, 5, 180}, nil), "invalid fixed option length")
	}
}

func TestTCPOptionBoundaryAcrossQueries(t *testing.T) {
	for _, expr := range []string{
		"eth/ipv4/tcp where tcp.options.MSS.value == 1460",
		"eth/(ipv4|ipv6)/tcp where tcp.options.MSS.value == 1460",
	} {
		r := New(t, expr)
		r.MustMatch(t, tcpWithRawOptions(t, 15, append(bytes.Repeat([]byte{1}, 36), 2, 4, 5, 180), nil), "MSS after 36 NOPs")
		r.MustReject(t, tcpWithRawOptions(t, 15, bytes.Repeat([]byte{1}, 40), []byte{2, 4, 5, 180}), "40 NOPs end exactly at payload")
		for _, n := range []byte{0, 1, 9} {
			r.MustReject(t, tcpWithRawOptions(t, 7, []byte{2, 4, 5, 180, 99, n, 0, 0}, nil), "malformed unknown after a matching MSS")
		}
		r.MustReject(t, tcpWithRawOptions(t, 7, []byte{2, 4, 5, 180, 3, 2, 7, 0}, nil), "unqueried WS has invalid length")
	}
	for _, expr := range []string{
		"eth/ipv4/tcp where tcp.options.TS.tsval == 1",
		"eth/ipv4/tcp where tcp.options.SACK.kind == 5",
		"eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7",
	} {
		r := New(t, expr)
		r.MustReject(t, tcpWithRawOptions(t, 6, []byte{1, 1, 1, 1}, []byte{2, 4, 5, 180, 3, 3, 7, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}), "payload cannot satisfy another option query")
	}
}

func TestTCPDeclaredHeaderLength(t *testing.T) {
	r := New(t, "eth/ipv4/tcp")
	r.MustMatch(t, tcpWithRawOptions(t, 5, nil, nil), "20-byte header")
	r.MustMatch(t, tcpWithRawOptions(t, 15, bytes.Repeat([]byte{1}, 40), nil), "60-byte header")
	for n := byte(0); n < 5; n++ {
		r.MustReject(t, tcpWithRawOptions(t, n, nil, nil), "header shorter than fixed prefix")
	}
	r.MustReject(t, tcpWithRawOptions(t, 6, []byte{1, 1, 1}, nil), "declared header exceeds packet")
}

func rawChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

package dsltest

import "testing"

func TestSliceLiteralWidth(t *testing.T) {
	for _, expr := range []string{
		"eth/ipv4/tcp[dport[8:16] == -1]",
		"eth/ipv4/tcp[dport[8:16] in [-1]]",
		"eth/ipv4/tcp where tcp.dport[8:16] == -1",
		"eth/ipv4/tcp[dport[8:16] == 255]",
		"eth/ipv4/tcp[dport[8:16] in [255]]",
	} {
		t.Run(expr, func(t *testing.T) {
			r := New(t, expr)
			for _, port := range []uint16{0, 1, 254, 255, 256, 511, 65535} {
				if got := r.Match(t, BuildEthIPv4TCP(t, 12345, port)); got != (port&255 == 255) {
					t.Errorf("port %d: match=%v", port, got)
				}
			}
		})
	}
}

func TestSliceInListUsesExtractedBits(t *testing.T) {
	for _, span := range []string{"0:8", "4:12", "8:16"} {
		for _, suffix := range []string{" == -1", " in [-1]", " == 255", " in [255]"} {
			t.Run(span+suffix, func(t *testing.T) {
				r := New(t, "eth/ipv4/tcp[dport["+span+"]"+suffix+"]")
				shift := uint(0)
				if span == "0:8" {
					shift = 8
				}
				if span == "4:12" {
					shift = 4
				}
				for _, port := range []uint16{0, 254, 255, 256, 4080, 65280, 65535} {
					want := (port>>shift)&255 == 255
					if got := r.Match(t, BuildEthIPv4TCP(t, 12345, port)); got != want {
						t.Errorf("port %d: match=%v, want %v", port, got, want)
					}
				}
			})
		}
	}
}

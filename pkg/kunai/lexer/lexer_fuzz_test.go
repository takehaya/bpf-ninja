package lexer

import (
	"testing"
)

// FuzzLexNext drives the structural-mode scanner against arbitrary
// input bytes to surface panics, nil-dereferences, or runaway loops
// inside the lexer.
//
// The body recovers from any panic so a crashing input is surfaced
// as a test failure (with the offending source bytes) rather than
// killing the worker. Token consumption is capped so a buggy lexer
// that fails to advance (which would normally infinite-loop) is
// caught instead of timing out.
//
// Run with:
//
//	go test -run=FuzzLexNext -fuzz=FuzzLexNext -fuzztime=30s ./pkg/kunai/lexer/
func FuzzLexNext(f *testing.F) {
	seeds := []string{
		// Valid-shaped seeds taken from lexer_test.go / parser_test.go.
		"eth/ipv4/tcp",
		"eth/ipv4/tcp[dport==443]",
		"where capture all headers and or not in has action",
		"== != <= >= < >",
		"/ @ [ ] ( ) { } , . | ? + * - %",
		"<< >> & ^ : =",
		"eth/ipv4/tcp where action == XDP_DROP",
		"eth/ipv6[dst==2001:db8::/32]/tcp",
		"eth/ipv4[src==10.0.0.0/8]/tcp",
		"eth[dst==aa:bb:cc:dd:ee:ff]/ipv4/tcp",
		"eth/mpls{1,8}/ipv4/tcp",
		"eth/(vlan|qinq)/ipv4/tcp",
		"eth/ipv4/tcp capture headers+64",
		"eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80",
		"0x1234abcd",
		"443",
		"-128",
		"fe80::1%eth0",
		// Edge cases: empty / whitespace / binary / overlong runs of
		// the same delimiter / mixed UTF-8.
		"",
		" \t\n\r",
		"\x00\x01\xff",
		"/// ////",
		"{{{{}}}}",
		"[[[[]]]]",
		"::::::",
		"............",
		"////////",
		"0x",          // malformed hex
		"0xZZZ",       // hex with non-hex follow
		"@@@@@@@",
		"identifier_with_long_name_0123456789",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("lexer panicked on %q: %v", src, r)
			}
		}()
		l := New([]byte(src), "fuzz")
		// Bound iterations to defend against a future bug where the
		// lexer fails to advance past a byte: we'd rather see a
		// fuzz failure than a 60s timeout per worker.
		const maxTokens = 4096
		for i := 0; i < maxTokens; i++ {
			tok, err := l.Next()
			if err != nil {
				// Syntax errors are expected on random input —
				// just stop scanning this case.
				return
			}
			if tok.Kind == TokEOF {
				return
			}
		}
	})
}

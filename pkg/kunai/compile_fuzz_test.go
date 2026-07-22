package kunai

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// FuzzCompile exercises the end-to-end DSL pipeline (lexer → parser →
// resolve → codegen) against arbitrary string inputs to surface
// panics, nil-dereferences, runaway recursion, or other crashes.
//
// Returning an error for invalid input is fine — only panics and
// other unrecoverable failures count as fuzz failures.
//
// Run with:
//
//	go test -run=FuzzCompile -fuzz=FuzzCompile -fuzztime=30s ./pkg/kunai/
//
// Seed corpus mirrors the headline cases from compile_test.go and
// parser_test.go so the entry corpus exercises every major DSL
// surface (layer chains, predicates, where clauses, captures,
// quantifiers, alternation, IPv4/IPv6/MAC literals, bit-slices, …).
func FuzzCompile(f *testing.F) {
	seeds := []string{
		// Empty / minimal — exercise short-input edge cases.
		"",
		" ",
		"eth",
		"eth/ipv4",
		"eth/ipv4/tcp",
		"eth/ipv4/udp",
		"eth/ipv6/tcp",
		// Predicates: integer, IPv4, IPv6, MAC, CIDR.
		"eth/ipv4/tcp[dport==443]",
		"eth/ipv4/tcp[dport in [80, 443, 8080, 8443]]",
		"eth/ipv4[src==10.0.0.1]/tcp",
		"eth/ipv4[dst==10.0.0.0/8]/tcp",
		"eth/ipv4[src==192.168.0.0/16]/tcp[dport==443]",
		"eth/ipv6[src==fe80::1]/tcp",
		"eth/ipv6[dst==2001:db8::/32]/tcp",
		"eth/ipv6[src==2001:db8::1/128]/tcp",
		"eth[dst==de:ad:be:ef:00:01]/ipv4/tcp",
		"eth[src!=00:11:22:33:44:55]/ipv4/tcp",
		// Quantifiers: ?, +, *, {n,m}.
		"eth/vlan?/ipv4/tcp",
		"eth/qinq?/vlan?/ipv4/tcp",
		"eth/mpls+/ipv4/tcp",
		"eth/mpls*/ipv4/tcp",
		"eth/vlan{1,3}/ipv4/tcp",
		"eth/mpls{1,4}/ipv4/tcp",
		"eth/mpls{2,2}/ipv4/tcp",
		// Alternation, including nested.
		"eth/(vlan|qinq)/ipv4/tcp",
		"eth/(ipv4|ipv6)/tcp",
		"eth/(ipv4|ipv6)/tcp[dport==443]",
		"eth/((vlan|qinq)|ipv4)",
		// where clauses.
		"eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80",
		"eth/ipv4/tcp where ipv4.total_length == 100",
		"eth/ipv4/tcp where (tcp.dport == 80 or tcp.dport == 443) and tcp.sport > 1024",
		"eth/ipv4/tcp where tcp.dport & 0xff == 80",
		"eth/ipv4/tcp where tcp.dport >> 4 == 0",
		"eth/ipv4/tcp where true",
		"eth/ipv4/tcp where false",
		"eth/ipv4/tcp where tcp.dport",
		"eth/ipv6/tcp where ipv6.src == ipv6.dst",
		"eth/ipv6/tcp where ipv6.src < ipv6.dst",
		"eth/ipv6/tcp where ipv6.src[0:32] == 0x20010db8",
		// capture clauses.
		"eth/ipv4/tcp capture headers+64",
		"eth/ipv4/tcp capture all",
		"eth/ipv4/tcp capture ipv4.src, tcp.dport",
		"eth/ipv4/tcp capture absolute 96",
		// Encapsulated / multi-label chains.
		"eth/ipv4@outer/udp/vxlan[vni==100]/ipv4@inner/tcp[dport==80]",
		"eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.exists",
		// Negative / malformed seeds — exercise error paths cleanly.
		"eth/ipv4/",
		"eth/bogus/tcp",
		"eth/ipv4@/tcp",
		"eth/ipv4[src==10.0.0.0/8",
		"eth/ipv4+?/tcp",
		"eth/mpls{5,3}/ipv4",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		// We only care that Compile does not panic. Returning an
		// error for invalid input is fine; the host-agnostic
		// zero Capabilities keeps the fuzz target target-agnostic
		// (no XDP-specific atoms admitted).
		_, _ = Compile(expr, codegen.Capabilities{})
	})
}

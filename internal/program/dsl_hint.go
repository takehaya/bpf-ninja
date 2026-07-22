package program

import (
	"fmt"
	"strings"
)

// pcapQualifiers is the set of bare-word tokens that signal a user
// typed tcpdump/pcap-filter syntax (e.g., "tcp port 443", "host
// 10.0.0.1", "src net 10.0.0.0/8") instead of the kunai DSL chain
// form. Triggered only on parse failure — valid DSL doesn't reach
// this code path, so false positives are structurally impossible.
var pcapQualifiers = map[string]bool{
	"host": true, "src": true, "dst": true, "port": true,
	"net": true, "proto": true, "broadcast": true, "multicast": true,
	"less": true, "greater": true, "gateway": true,
	"ether": true, "ip6": true, "arp": true, "rarp": true, "atalk": true,
}

// dslHintFor returns a one-line "next thing to try" suggestion when
// kunai.Compile rejects expr. The hint is appended to the wrapped
// error by compileFilter so the user sees both the structured DSL
// parse error and a copy-pasteable workaround.
func dslHintFor(expr string) string {
	tokens := strings.Fields(strings.ToLower(expr))
	for _, t := range tokens {
		if pcapQualifiers[t] {
			return fmt.Sprintf("this looks like tcpdump/pcap-filter syntax. "+
				"either run with --cbpf to enable the legacy syntax (e.g., "+
				"'--cbpf \"%s\"'), or convert to kunai DSL (see 'bpf-ninja "+
				"--dsl-help' for examples)", expr)
		}
	}

	// Heuristic: single bare protocol layer (no '/' anywhere) usually
	// means the user forgot the chain root. Suggest adding eth/...
	if !strings.ContainsAny(expr, "/[(@") {
		return fmt.Sprintf("DSL chains start from a packet entry layer. "+
			"try 'eth/ipv4/%s' or see 'bpf-ninja --dsl-help' for the "+
			"layer-chain grammar", strings.TrimSpace(expr))
	}

	return "run 'bpf-ninja --dsl-help' for grammar + examples, or " +
		"'--dump-asm filter <expr>' to inspect what the compiler produced"
}

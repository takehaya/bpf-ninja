// Package hookabi holds the BTF conventions shared by inject-run (which
// writes them) and the capture (which reads them): the decl tags on
// generated hooks and the rule for which key and value bytes may be shown.
// It depends only on cilium/ebpf/btf.
package hookabi

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// HookTag is the func-level BTF decl tag on every hook inject-run generates.
// The verifier does not interpret it.
const HookTag = "bpf-ninja:hook"

const sizePrefix = "bpf-ninja:"

// SizeTag is the func-level decl tag carrying an untyped key or value size:
// name is "key" or "value".
func SizeTag(name string, size uint32) string {
	return fmt.Sprintf("%s%s_size=%d", sizePrefix, name, size)
}

// SizeTags parses the key and value sizes from a function's decl tags.
func SizeTags(tags []string) map[string]uint32 {
	out := map[string]uint32{}
	for _, tag := range tags {
		rest, ok := strings.CutPrefix(tag, sizePrefix)
		if !ok {
			continue
		}
		for _, name := range []string{"key", "value"} {
			if v, ok := strings.CutPrefix(rest, name+"_size="); ok {
				if n, err := strconv.ParseUint(v, 10, 32); err == nil {
					out[name] = uint32(n)
				}
			}
		}
	}
	return out
}

// Plain reports whether every byte of t is plain data: integers, enums and
// bools, or arrays, structs and unions made only of those. Pointers and
// Opaque structs are not plain, nor is anything containing them, so their
// bytes are never shown or sized.
func Plain(t btf.Type) bool { return plain(t, 0) }

// Opaque reports whether t is a bpf_* struct (timers, locks, list and rb
// nodes, kptr holders and the like), kernel-managed storage whose bytes are
// never sized, shown or recorded. The uapi LPM trie key structs, a __u32
// prefixlen and its data bytes, are plain.
func Opaque(t *btf.Struct) bool {
	switch t.Name {
	case "bpf_lpm_trie_key", "bpf_lpm_trie_key_hdr", "bpf_lpm_trie_key_u8":
		return false
	}
	return strings.HasPrefix(t.Name, "bpf_")
}

func plain(t btf.Type, depth int) bool {
	if depth > 32 {
		return false
	}
	switch t := btf.UnderlyingType(t).(type) {
	case *btf.Int, *btf.Enum:
		return true
	case *btf.Array:
		return plain(t.Type, depth+1)
	case *btf.Struct:
		if Opaque(t) {
			return false
		}
		for _, m := range t.Members {
			if !plain(m.Type, depth+1) {
				return false
			}
		}
		return true
	case *btf.Union:
		for _, m := range t.Members {
			if !plain(m.Type, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

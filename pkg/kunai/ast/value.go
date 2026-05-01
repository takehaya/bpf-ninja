package ast

import "fmt"

// ValueKind classifies literal values inside predicates.
type ValueKind int

const (
	ValInt    ValueKind = iota // decimal or hex integer
	ValIPv4                    // dotted-quad IPv4 address
	ValIPv6                    // colon-separated IPv6 address (may be shortened)
	ValMAC                     // 6 hex octets separated by colons
	ValCIDR                    // host/prefix (v4 or v6, AF indicates)
	ValRange                   // N..M integer range
	ValString                  // "quoted" string literal (MVP-unsupported)
	ValIdent                   // bare identifier like XDP_PASS
)

func (v ValueKind) String() string {
	switch v {
	case ValInt:
		return "int"
	case ValIPv4:
		return "ipv4"
	case ValIPv6:
		return "ipv6"
	case ValMAC:
		return "mac"
	case ValCIDR:
		return "cidr"
	case ValRange:
		return "range"
	case ValString:
		return "string"
	case ValIdent:
		return "ident"
	}
	return fmt.Sprintf("ValueKind(%d)", int(v))
}

// Value is a literal value with its raw source text preserved for diagnostics.
type Value struct {
	Kind ValueKind
	Raw  string // original text; always filled, used for error messages

	// ValInt
	Int uint64

	// ValIPv4 (and ValCIDR when AF==4)
	V4 [4]byte

	// ValIPv6 (and ValCIDR when AF==6)
	V6 [16]byte

	// ValCIDR
	AF     int // 4 or 6
	Prefix int // 0..32 or 0..128

	// ValMAC
	MAC [6]byte

	// ValString
	Str string

	// ValIdent
	Ident string

	// ValRange
	RangeLo uint64
	RangeHi uint64

	Pos Position
}

package lexer

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
)

// classifyValue turns a value-mode run of characters into a typed
// ast.Value. Checks are ordered so that unambiguous discriminators win:
// ".." marks a range, "/" marks a CIDR, four dotted octets without
// colons are IPv4, `XX:XX:XX:XX:XX:XX` (17 chars, 5 colons, hex only)
// is a MAC, any other colon-bearing form is an IPv6 address, digits
// or 0x-prefixed digits are an integer, and an identifier shape is a
// bare identifier (used for XDP_* action constants).
func classifyValue(raw string, pos ast.Position) (*ast.Value, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty value")
	}

	if loStr, hiStr, ok := strings.Cut(raw, ".."); ok {
		return buildRange(raw, loStr, hiStr, pos)
	}
	if strings.ContainsRune(raw, '/') {
		return buildCIDR(raw, pos)
	}
	if strings.Count(raw, ".") == 3 && !strings.ContainsRune(raw, ':') {
		return buildIPv4(raw, pos)
	}
	if strings.ContainsRune(raw, ':') {
		if isMACShape(raw) {
			return buildMAC(raw, pos)
		}
		return buildIPv6(raw, pos)
	}
	if isIntegerLiteral(raw) {
		return buildInt(raw, pos)
	}
	if isIdentLiteral(raw) {
		return &ast.Value{Kind: ast.ValIdent, Raw: raw, Ident: raw, Pos: pos}, nil
	}
	return nil, fmt.Errorf("unrecognized value %q", raw)
}

func buildRange(raw, loStr, hiStr string, pos ast.Position) (*ast.Value, error) {
	if loStr == "" || hiStr == "" {
		return nil, fmt.Errorf("range %q: empty side of '..'", raw)
	}
	lo, err := strconv.ParseUint(loStr, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("range lower bound %q: %v", loStr, err)
	}
	hi, err := strconv.ParseUint(hiStr, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("range upper bound %q: %v", hiStr, err)
	}
	if lo > hi {
		return nil, fmt.Errorf("range %q: lower %d exceeds upper %d", raw, lo, hi)
	}
	return &ast.Value{Kind: ast.ValRange, Raw: raw, RangeLo: lo, RangeHi: hi, Pos: pos}, nil
}

func buildCIDR(raw string, pos ast.Position) (*ast.Value, error) {
	ip, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, fmt.Errorf("CIDR %q: %v", raw, err)
	}
	// Reject non-zero host bits per dsl-types.md §4.5: the user's
	// intent is ambiguous between "this single host" and "this
	// subnet", so demand explicit phrasing.
	if !ip.Equal(ipnet.IP) {
		_, bits := ipnet.Mask.Size()
		networkStr := ipnet.String()
		hostStr := ipForHost(ip, bits)
		return nil, fmt.Errorf(
			"CIDR %q has host bits set; network would be %s (suggestion: %s for the subnet, or %s/%d for the single host)",
			raw, networkStr, networkStr, hostStr, bits,
		)
	}
	ones, _ := ipnet.Mask.Size()
	if len(ipnet.IP) == net.IPv4len {
		var v4 [4]byte
		copy(v4[:], ipnet.IP)
		return &ast.Value{Kind: ast.ValCIDR, Raw: raw, AF: 4, V4: v4, Prefix: ones, Pos: pos}, nil
	}
	var v6 [16]byte
	copy(v6[:], ipnet.IP)
	return &ast.Value{Kind: ast.ValCIDR, Raw: raw, AF: 6, V6: v6, Prefix: ones, Pos: pos}, nil
}

// ipForHost returns the original IP (pre-masking) as a string so the
// suggestion `host/<full-prefix>` is well-formed.
func ipForHost(ip net.IP, bits int) string {
	if bits == 32 {
		v4 := ip.To4()
		if v4 != nil {
			return v4.String()
		}
	}
	return ip.String()
}

func buildIPv4(raw string, pos ast.Position) (*ast.Value, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address %q", raw)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %q", raw)
	}
	var out [4]byte
	copy(out[:], v4)
	return &ast.Value{Kind: ast.ValIPv4, Raw: raw, V4: out, Pos: pos}, nil
}

func buildIPv6(raw string, pos ast.Position) (*ast.Value, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address %q", raw)
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("invalid IPv6 address %q", raw)
	}
	var out [16]byte
	copy(out[:], v6)
	return &ast.Value{Kind: ast.ValIPv6, Raw: raw, V6: out, Pos: pos}, nil
}

func buildMAC(raw string, pos ast.Position) (*ast.Value, error) {
	var mac [6]byte
	parts := strings.Split(raw, ":")
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("MAC %q: octet %q: %v", raw, p, err)
		}
		mac[i] = byte(n)
	}
	return &ast.Value{Kind: ast.ValMAC, Raw: raw, MAC: mac, Pos: pos}, nil
}

func buildInt(raw string, pos ast.Position) (*ast.Value, error) {
	if strings.HasPrefix(raw, "-") {
		// Signed literal: must fit in int64; the value is then stored
		// as its 2's-complement uint64 so the resolver can narrow it
		// to any target Int<N> per dsl-types.md §4.1.
		signed, err := strconv.ParseInt(raw, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %v", raw, err)
		}
		// #nosec G115 — intentional reinterpretation as uint64.
		return &ast.Value{Kind: ast.ValInt, Raw: raw, Int: uint64(signed), Pos: pos}, nil
	}
	v, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid integer %q: %v", raw, err)
	}
	return &ast.Value{Kind: ast.ValInt, Raw: raw, Int: v, Pos: pos}, nil
}

// isMACShape is a cheap format test for `XX:XX:XX:XX:XX:XX`. It runs
// before the actual hex parse so that ambiguous strings (IPv6 without
// this shape) go straight to the IPv6 parser. buildMAC does the full
// hex validation.
func isMACShape(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i := range 17 {
		if (i+1)%3 == 0 {
			if s[i] != ':' {
				return false
			}
			continue
		}
		if !isHexChar(s[i]) {
			return false
		}
	}
	return true
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	// Optional leading minus: a single '-' must be followed by at
	// least one digit (or a hex prefix). We strip it before the
	// usual hex/decimal classification so the rest of the rules stay
	// untouched.
	if s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		s = s[1:]
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if len(s) == 2 {
			return false
		}
		for i := 2; i < len(s); i++ {
			if !isHexChar(s[i]) {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isIdentLiteral(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentCont(s[i]) {
			return false
		}
	}
	return true
}

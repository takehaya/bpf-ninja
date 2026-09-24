package resolve

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

func TestLiteralSignWidthBoundaries(t *testing.T) {
	for _, field := range []struct {
		name, chain string
		bits        int
	}{
		{"ttl", "eth/ipv4", 8}, {"dport", "eth/ipv4/tcp", 16}, {"seq", "eth/ipv4/tcp", 32},
	} {
		max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(field.bits)), big.NewInt(1))
		min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(field.bits-1)))
		values := []struct {
			n  *big.Int
			ok bool
		}{
			{big.NewInt(-1), true}, {max, true}, {min, true},
			{new(big.Int).Add(max, big.NewInt(1)), false}, {new(big.Int).Sub(min, big.NewInt(1)), false},
			{new(big.Int).SetUint64(^uint64(0)), false},
		}
		proto := "ipv4"
		if field.name != "ttl" {
			proto = "tcp"
		}
		for _, value := range values {
			for _, literal := range []string{value.n.String(), fmt.Sprintf("%#x", value.n)} {
				for _, expr := range []string{
					fmt.Sprintf("%s[%s == %s]", field.chain, field.name, literal),
					fmt.Sprintf("%s where (%s.%s) == (%s)", field.chain, proto, field.name, literal),
					fmt.Sprintf("%s[%s in [%s]]", field.chain, field.name, literal),
				} {
					t.Run(expr, func(t *testing.T) {
						f, err := parser.Parse(expr, "sign.dsl", nil)
						if err != nil {
							t.Fatal(err)
						}
						_, err = Resolve(f, loadVocab(t), nil)
						if (err == nil) != value.ok {
							t.Fatalf("error = %v, want valid=%v", err, value.ok)
						}
						if err != nil && (!strings.HasPrefix(err.Error(), "1:") || !strings.Contains(err.Error(), "does not fit")) {
							t.Fatalf("missing positioned width diagnostic: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestLiteral64BitBoundaries(t *testing.T) {
	v := map[string]*vocab.ProtocolSpec{"wide": {Name: "wide", HeaderName: "wide_h", Fields: []vocab.Field{{Name: "n", Bits: 64}}}}
	for _, literal := range []string{"18446744073709551615", "0xffffffffffffffff", "-9223372036854775808", "-0x8000000000000000", "-0", "0"} {
		for _, expr := range []string{"wide[n == " + literal + "]", "wide where (wide.n) == (" + literal + ")", "wide[n in [" + literal + "]]"} {
			f, err := parser.Parse(expr, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Resolve(f, v, nil); err != nil {
				t.Fatalf("%s: %v", expr, err)
			}
		}
	}
	for _, literal := range []string{"18446744073709551616", "0x10000000000000000", "-9223372036854775809", "-0x8000000000000001"} {
		for _, expr := range []string{"wide[n == " + literal + "]", "wide where wide.n == " + literal} {
			if _, err := parser.Parse(expr, "", nil); err == nil {
				t.Fatalf("overflow accepted: %s", expr)
			}
		}
	}
}

func TestSliceLiteralFit(t *testing.T) {
	for _, value := range []string{"256", "0x100", "-129", "-0x81"} {
		for _, expr := range []string{"eth/ipv4/tcp[dport[8:16] == " + value + "]", "eth/ipv4/tcp[dport[8:16] in [" + value + "]]", "eth/ipv4/tcp where tcp.dport[8:16] == " + value} {
			resolveErr(t, expr, nil, "does not fit")
		}
	}
}

package vocab

import (
	"strings"
	"testing"
	"testing/fstest"
)

// The aux-gating helpers (computeAuxGating → gatingFromSelect →
// mergeBitFieldsToMask) only get exercised on the success path by the
// bundled GTP vocab. Their error branches — multi-case gating,
// non-zero explicit case, byte-straddling key, multi-byte key span —
// had only indirect coverage. These tests craft synthetic .p4 that
// reaches each branch through the real Load() pipeline and pins the
// diagnostic.

// loadGatingP4 wraps a single synthetic .p4 source through the vocab
// loader. The source must declare a `foo_h` primary so the loader's
// primary-header convention is satisfied.
func loadGatingP4(t *testing.T, src string) error {
	t.Helper()
	fsys := fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
	_, err := Load(fsys, "vocab")
	return err
}

// TestGatingFromSelectRejectsMultipleExplicitCases pins that an
// entry-state select where the aux-extract is the default branch but
// more than one explicit case exists is rejected — the MVP gating
// model only inverts a single explicit case.
func TestGatingFromSelectRejectsMultipleExplicitCases(t *testing.T) {
	src := `header foo_h { bit<5> pad; bit<3> flags; }
header foo_opt_h { bit<8> data; }
parser P(packet_in pkt, out foo_h hdr, out foo_opt_h opt) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.flags) {
			0: accept;
			1: accept;
			default: parse_opt;
		}
	}
	state parse_opt {
		pkt.extract(opt);
		transition accept;
	}
}`
	err := loadGatingP4(t, src)
	if err == nil {
		t.Fatal("expected error for multi-case aux gating, got nil")
	}
	if !strings.Contains(err.Error(), "exactly one explicit case") {
		t.Errorf("err = %q; want 'exactly one explicit case'", err.Error())
	}
}

// TestGatingFromSelectRejectsNonZeroExplicitCase pins that the
// default→extract gating shape requires the lone explicit case to be
// all-zero (the gating predicate is "the OR of the key bits is
// non-zero"; a non-zero case value would make the negation wrong).
func TestGatingFromSelectRejectsNonZeroExplicitCase(t *testing.T) {
	src := `header foo_h { bit<5> pad; bit<3> flags; }
header foo_opt_h { bit<8> data; }
parser P(packet_in pkt, out foo_h hdr, out foo_opt_h opt) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.flags) {
			1: accept;
			default: parse_opt;
		}
	}
	state parse_opt {
		pkt.extract(opt);
		transition accept;
	}
}`
	err := loadGatingP4(t, src)
	if err == nil {
		t.Fatal("expected error for non-zero explicit gating case, got nil")
	}
	if !strings.Contains(err.Error(), "all-zero") {
		t.Errorf("err = %q; want 'all-zero'", err.Error())
	}
}

// TestMergeBitFieldsRejectsByteStraddle pins that a gating key whose
// bit window crosses a byte boundary is rejected — codegen emits a
// single byte read + mask, which a straddling field would corrupt.
func TestMergeBitFieldsRejectsByteStraddle(t *testing.T) {
	// `straddler` occupies bits [6,10): it crosses the byte-0/byte-1
	// boundary.
	src := `header foo_h { bit<6> pad; bit<4> straddler; bit<6> rest; }
header foo_opt_h { bit<8> data; }
parser P(packet_in pkt, out foo_h hdr, out foo_opt_h opt) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.straddler) {
			0: accept;
			default: parse_opt;
		}
	}
	state parse_opt {
		pkt.extract(opt);
		transition accept;
	}
}`
	err := loadGatingP4(t, src)
	if err == nil {
		t.Fatal("expected error for byte-straddling gating key, got nil")
	}
	if !strings.Contains(err.Error(), "straddles a byte boundary") {
		t.Errorf("err = %q; want 'straddles a byte boundary'", err.Error())
	}
}

// TestMergeBitFieldsRejectsMultiByteSpan pins that a multi-key gating
// tuple whose keys land in different bytes is rejected — the MVP
// single-byte read can't cover two bytes.
func TestMergeBitFieldsRejectsMultiByteSpan(t *testing.T) {
	// `a` is in byte 0 (bits [0,3)), `b` is in byte 1 (bits [8,11)).
	src := `header foo_h { bit<3> a; bit<5> pad0; bit<3> b; bit<5> pad1; }
header foo_opt_h { bit<8> data; }
parser P(packet_in pkt, out foo_h hdr, out foo_opt_h opt) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.a, hdr.b) {
			(0, 0): accept;
			default: parse_opt;
		}
	}
	state parse_opt {
		pkt.extract(opt);
		transition accept;
	}
}`
	err := loadGatingP4(t, src)
	if err == nil {
		t.Fatal("expected error for multi-byte gating key span, got nil")
	}
	if !strings.Contains(err.Error(), "span multiple bytes") {
		t.Errorf("err = %q; want 'span multiple bytes'", err.Error())
	}
}

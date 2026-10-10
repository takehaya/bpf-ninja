package vocab

import (
	"strings"
	"testing"
	"testing/fstest"
)

// writebackVocab is a minimal protocol with an extension stack whose
// @kunai_writeback targets `parent` in the primary header.
func writebackVocab(primary, parent string) fstest.MapFS {
	src := `header foo_h { ` + primary + ` }
@kunai_variable_tail[len_field=len, scale=8, mask=0xff]
@kunai_writeback[source=next, parent=foo.` + parent + `]
header foo_ext_h { bit<8> next; bit<8> len; bit<48> _o; }
parser P(packet_in pkt, out foo_h hdr, out foo_ext_h[16] exts) {
	state start {
		pkt.extract(hdr);
		transition select(hdr.next) {
			0: parse_ext;
			default: accept;
		}
	}
	state parse_ext {
		pkt.extract(exts.next);
		transition select(exts.last.next) {
			0: parse_ext;
			default: accept;
		}
	}
}`
	return fstest.MapFS{"vocab/foo.p4": &fstest.MapFile{Data: []byte(src)}}
}

// TestWritebackTargetMustBeOneByte pins the loader rule the write-back
// slot relies on: the target is a byte-aligned 8-bit field, because the
// slot holds one byte and codegen overlays exactly that byte. A 16-bit
// target and a 4-bit (unaligned) target are refused; an 8-bit one loads.
func TestWritebackTargetMustBeOneByte(t *testing.T) {
	if _, err := Load(writebackVocab("bit<8> a; bit<8> next; bit<16> len;", "next"), "vocab"); err != nil {
		t.Fatalf("8-bit target: %v", err)
	}
	for name, c := range map[string]struct{ primary, parent string }{
		"16-bit":    {"bit<8> a; bit<8> next; bit<16> wide;", "wide"},
		"unaligned": {"bit<4> hi; bit<4> lo; bit<8> next; bit<16> len;", "lo"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writebackVocab(c.primary, c.parent), "vocab")
			if err == nil {
				t.Fatal("expected the write-back target to be refused")
			}
			if !strings.Contains(err.Error(), "8-bit") {
				t.Errorf("error %q should name the 8-bit rule", err)
			}
		})
	}
}

package setmap

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseSetSpec(t *testing.T) {
	tests := []struct {
		in      string
		name    string
		path    string
		mapping []MapEntry
		wantErr string
	}{
		{in: "subs=/sys/fs/bpf/subs", name: "subs", path: "/sys/fs/bpf/subs"},
		{
			in:   "flows=/sys/fs/bpf/flows,key(imsi=arg:imsi,teid=arg:teid)",
			name: "flows", path: "/sys/fs/bpf/flows",
			mapping: []MapEntry{{Field: "imsi", Source: "arg:imsi"}, {Field: "teid", Source: "arg:teid"}},
		},
		{
			// shorthand: key(imsi) = key(imsi=arg:imsi)
			in: "s=/p,key(imsi)", name: "s", path: "/p",
			mapping: []MapEntry{{Field: "imsi", Source: "arg:imsi"}},
		},
		{in: "=/p", wantErr: "want NAME="},
		{in: "s=", wantErr: "empty pinned map path"},
		{in: "s=/p,keys(imsi)", wantErr: "expected key("},
		{in: "s=/p,key()", wantErr: "empty key"},
		{in: "s=/p,key(f=pkt:ipv4.src)", wantErr: "must be arg:"},
	}
	for _, tt := range tests {
		ref, err := ParseSetSpec(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseSetSpec(%q) err = %v, want containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSetSpec(%q): %v", tt.in, err)
			continue
		}
		if ref.Name != tt.name || ref.Path != tt.path {
			t.Errorf("ParseSetSpec(%q) = %+v", tt.in, ref)
		}
		if len(ref.Mapping) != len(tt.mapping) {
			t.Errorf("ParseSetSpec(%q) mapping = %+v, want %+v", tt.in, ref.Mapping, tt.mapping)
			continue
		}
		for i := range tt.mapping {
			if ref.Mapping[i] != tt.mapping[i] {
				t.Errorf("ParseSetSpec(%q) mapping[%d] = %+v, want %+v", tt.in, i, ref.Mapping[i], tt.mapping[i])
			}
		}
	}
}

func TestLayoutNaturalAlignment(t *testing.T) {
	specs, err := ParseSchema("imsi:u64,teid:u32")
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	fields, size := layout(specs)
	if size != 16 {
		t.Errorf("size = %d, want 16 (u64+u32 padded to 8-alignment)", size)
	}
	if fields[0].Off != 0 || fields[1].Off != 8 {
		t.Errorf("offsets = %d,%d, want 0,8", fields[0].Off, fields[1].Off)
	}

	// u16 then u64: u64 must align to 8, total padded to 16.
	specs2, _ := ParseSchema("a:u16,b:u64")
	f2, size2 := layout(specs2)
	if f2[1].Off != 8 || size2 != 16 {
		t.Errorf("a:u16,b:u64 → b@%d size %d, want b@8 size 16", f2[1].Off, size2)
	}
}

func TestBuildKeyPaddingAndErrors(t *testing.T) {
	def := &Definition{
		KeySize: 16,
		Fields: []KeyField{
			{Name: "imsi", Off: 0, Size: 8},
			{Name: "teid", Off: 8, Size: 4},
		},
	}

	key, err := def.BuildKey(map[string]string{"imsi": "0x0102030405060708", "teid": "0x3039"})
	if err != nil {
		t.Fatalf("BuildKey: %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("key len = %d, want 16", len(key))
	}
	// padding bytes (12..15) must be zero — hash covers the full key.
	for i := 12; i < 16; i++ {
		if key[i] != 0 {
			t.Errorf("padding byte %d = %#x, want 0", i, key[i])
		}
	}

	// partial key → error naming the missing field
	if _, err := def.BuildKey(map[string]string{"imsi": "1"}); err == nil || !strings.Contains(err.Error(), "teid") {
		t.Errorf("partial key err = %v, want mention of teid", err)
	}
	// unknown field
	if _, err := def.BuildKey(map[string]string{"imsi": "1", "teid": "2", "bogus": "3"}); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("unknown field err = %v, want mention of bogus", err)
	}
	// value too wide for field
	if _, err := def.BuildKey(map[string]string{"imsi": "1", "teid": "1099511627776"}); err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Errorf("overflow err = %v, want 'does not fit'", err)
	}
}

func TestParseSchemaIPv6(t *testing.T) {
	specs, err := ParseSchema("sid:ipv6")
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("specs = %+v", specs)
	}
	if f := specs[0]; f.Name != "sid" || f.Size != 16 || f.Align != 1 || !f.IsBytes {
		t.Errorf("spec = %+v, want {sid 16 align1 bytes}", f)
	}
}

func TestBuildKeyIPv6NetworkOrder(t *testing.T) {
	def := &Definition{
		KeySize: 16,
		Fields:  []KeyField{{Name: "sid", Off: 0, Size: 16, Align: 1, IsBytes: true}},
	}
	key, err := def.BuildKey(map[string]string{"sid": "fc00::1"})
	if err != nil {
		t.Fatalf("BuildKey: %v", err)
	}
	// Network order, verbatim: fc 00 00 ... 00 01 (matches wire bytes).
	want := make([]byte, 16)
	want[0] = 0xfc
	want[15] = 0x01
	if !bytes.Equal(key, want) {
		t.Errorf("key = %x, want %x", key, want)
	}
	// invalid literal
	if _, err := def.BuildKey(map[string]string{"sid": "nope"}); err == nil || !strings.Contains(err.Error(), "invalid IPv6") {
		t.Errorf("invalid-IP err = %v", err)
	}
}

func TestCreateRejectsIPv6Value(t *testing.T) {
	// ipv6 is a key-only type; the value guard runs before map creation.
	if err := Create("/sys/fs/bpf/unused", "sid:ipv6", "tag:ipv6", 8); err == nil || !strings.Contains(err.Error(), "single u8/u16/u32/u64 tag") {
		t.Errorf("ipv6 value err = %v", err)
	}
}

func TestParseFieldValues(t *testing.T) {
	fields, tag, hasTag, err := ParseFieldValues([]string{"imsi=999990000000001", "teid=0x3039", "tag=7"})
	if err != nil {
		t.Fatalf("ParseFieldValues: %v", err)
	}
	if fields["imsi"] != "999990000000001" || fields["teid"] != "0x3039" {
		t.Errorf("fields = %v", fields)
	}
	if !hasTag || tag != 7 {
		t.Errorf("tag = %d hasTag=%v, want 7 true", tag, hasTag)
	}

	if _, _, _, err := ParseFieldValues([]string{"imsi"}); err == nil {
		t.Error("expected error for missing =value")
	}
	if _, _, _, err := ParseFieldValues([]string{"a=1", "a=2"}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("dup err = %v", err)
	}
}

func TestParseSetSpecTrimAndDup(t *testing.T) {
	// whitespace-polluted field/source get trimmed
	ref, err := ParseSetSpec("s=/p,key( imsi = arg:imsi )")
	if err != nil {
		t.Fatalf("ParseSetSpec trim: %v", err)
	}
	if ref.Mapping[0].Field != "imsi" || ref.Mapping[0].Source != "arg:imsi" {
		t.Errorf("trimmed mapping = %+v", ref.Mapping[0])
	}
	// duplicate field mapping is rejected
	if _, err := ParseSetSpec("s=/p,key(imsi=arg:a,imsi=arg:b)"); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("dup field err = %v", err)
	}
	// empty field name
	if _, err := ParseSetSpec("s=/p,key(=arg:imsi)"); err == nil || !strings.Contains(err.Error(), "empty key field") {
		t.Errorf("empty field err = %v", err)
	}
}

func TestCreateRejectsReservedKeyField(t *testing.T) {
	// A "tag" key field can never be addressed by `set add`.
	if err := Create("/sys/fs/bpf/unused", "tag:u32", "", 8); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("reserved-key err = %v", err)
	}
}

func TestCreateRejectsMultiFieldValue(t *testing.T) {
	if err := Create("/sys/fs/bpf/unused", "imsi:u64", "a:u8,b:u16", 8); err == nil || !strings.Contains(err.Error(), "single") {
		t.Errorf("multi-field value err = %v, want 'single ... tag'", err)
	}
}

func TestParseSchemaRejectsDuplicateField(t *testing.T) {
	if _, err := ParseSchema("imsi:u64,imsi:u32"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("dup field err = %v, want 'duplicate'", err)
	}
}

// newIPv6SetMap creates an in-memory hash map with a single ipv6 SID key.
func newIPv6SetMap(t *testing.T) *ebpf.Map {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a BPF map")
	}
	fields, size := layout([]FieldSpec{{Name: "sid", Size: 16, Align: 1, IsBytes: true}})
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "xdpninja_sidtest", Type: ebpf.Hash,
		KeySize: size, ValueSize: 4, MaxEntries: 4,
		Key:   synthesizeType("xdpninja_set_key", fields, size),
		Value: intType(4),
	})
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// TestIPv6BTFRoundTrip pins that the synthesize side (fieldType, __u8[16]
// array) and the describe side (resolveFieldType) agree: a map created
// with an ipv6 key reads back as a 16-byte byte-string scalar field.
func TestIPv6BTFRoundTrip(t *testing.T) {
	def, err := describe(newIPv6SetMap(t))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !def.IsScalar || len(def.Fields) != 1 {
		t.Fatalf("def = %+v, want a single scalar field", def)
	}
	if f := def.Fields[0]; f.Name != "sid" || f.Size != 16 || f.Off != 0 || !f.IsBytes {
		t.Errorf("field = %+v, want {sid 16 off0 bytes}", f)
	}
}

// TestIPv6AddListSchema round-trips an SRv6 SID through Add / List /
// Schema and checks it renders as an IPv6 literal, not a number.
func TestIPv6AddListSchema(t *testing.T) {
	def, err := describe(newIPv6SetMap(t))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if err := def.Add(map[string]string{"sid": "fc00::1"}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}
	var list bytes.Buffer
	if err := def.List(&list); err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := list.String(); !strings.Contains(got, "sid=fc00::1 tag=1") {
		t.Errorf("List = %q, want to contain 'sid=fc00::1 tag=1'", got)
	}
	var schema bytes.Buffer
	def.Schema(&schema)
	if got := schema.String(); !strings.Contains(got, "sid") || !strings.Contains(got, "ipv6") {
		t.Errorf("Schema = %q, want sid + ipv6", got)
	}
}

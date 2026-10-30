package output

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/takehaya/bpf-ninja/internal/capture"
)

func TestHookInterfacesAndMerge(t *testing.T) {
	for _, fast := range []string{"0", "1"} {
		t.Run("fast="+fast, func(t *testing.T) {
			t.Setenv("BPF_NINJA_FAST_PCAPNG", fast)
			base := filepath.Join(t.TempDir(), "hooks.pcapng")
			cfg := Config{Hooks: []string{"hook_a", "hook_b", "hook_c"}}
			ts := time.Unix(100, 0)
			// Hook mode uses the fast writer with either environment setting.
			// CPU 1 has all earlier timestamps; round-robin merging would fail.
			for cpu := 0; cpu < 2; cpu++ {
				w, err := NewWriter(fmt.Sprintf("%s.cpu%d", base, cpu), cfg)
				if err != nil {
					t.Fatal(err)
				}
				for site := 1; site <= 3; site++ {
					p := capture.Packet{Timestamp: ts.Add(time.Duration(site + (1-cpu)*10)), Data: []byte{byte(cpu), byte(site)}, SiteID: uint8(site), PacketID: uint64(cpu)<<48 | 1}
					if err := w.Write(p); err != nil {
						t.Fatal(err)
					}
				}
				if w.EPBSize(2) != EPBSizeID(2) {
					t.Fatal("incorrect byte accounting")
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Empty config exercises detection used by standalone/tag merge.
			if err := MergeShardFiles(base, 2, Config{}); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(base)
			if err != nil {
				t.Fatal(err)
			}
			r, err := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 6; i++ {
				data, ci, err := r.ReadPacketData()
				if err != nil {
					t.Fatal(err)
				}
				if ci.InterfaceIndex != i%3 || !bytes.Equal(data, []byte{byte(1 - i/3), byte(i%3 + 1)}) {
					t.Fatalf("record %d: iface=%d data=%x", i, ci.InterfaceIndex, data)
				}
			}
			if _, _, err := r.ReadPacketData(); err != io.EOF {
				t.Fatalf("end=%v", err)
			}
			if r.NInterfaces() != 3 {
				t.Fatalf("interfaces=%d", r.NInterfaces())
			}
			for i, name := range cfg.Hooks {
				intf, err := r.Interface(i)
				if err != nil {
					t.Fatal(err)
				}
				if intf.Name != name || intf.Description != fmt.Sprintf("bpf-ninja capture site_id=%d", i+1) {
					t.Fatalf("interface %d: %+v", i, intf)
				}
			}
			want := []uint64{1<<48 | 1, 1<<48 | 1, 1<<48 | 1, 1, 1, 1}
			if got := epbPacketIDs(t, raw); !slices.Equal(got, want) {
				t.Fatalf("ids=%x", got)
			}
		})
	}
}

func TestHookInvalidRecords(t *testing.T) {
	for _, p := range []capture.Packet{{}, {PacketID: 1}, {SiteID: 1}, {SiteID: 4, PacketID: 1}} {
		w, err := NewWriter(filepath.Join(t.TempDir(), "bad.pcapng"), Config{Hooks: []string{"a", "b", "c"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Write(p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
		if err := w.Close(); err == nil {
			t.Fatal("failure must remain terminal")
		}
	}
	names := make([]string, 256)
	for i := range names {
		names[i] = fmt.Sprintf("hook_%d", i)
	}
	w, err := NewWriter(filepath.Join(t.TempDir(), "max.pcapng"), Config{Hooks: names[:255]})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{{Hooks: []string{"a"}, IsFexit: true, Actions: []ActionName{{Value: 2, Name: "PASS"}}}, {Hooks: []string{"a"}, MultiPoint: true, Actions: []ActionName{{Value: 2, Name: "PASS"}}}, {Hooks: []string{"a", "a"}}, {Hooks: []string{""}}, {Hooks: names}} {
		if _, err := NewWriter(filepath.Join(t.TempDir(), "bad.pcapng"), cfg); err == nil {
			t.Fatalf("accepted config %+v", cfg)
		}
	}
}

func TestHookMergeRejectsDamage(t *testing.T) {
	for _, damage := range []string{"truncated", "header-only", "interface", "id", "option", "block-type", "short-epb", "caplen", "caplen-size", "option-size", "option-end", "trailer", "unaligned", "oversize"} {
		t.Run(damage, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "bad.pcapng")
			cfg := Config{Hooks: []string{"a"}}
			w, err := NewWriter(base+".cpu0", cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Write(capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{1}, SiteID: 1, PacketID: 1}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(base + ".cpu0")
			if err != nil {
				t.Fatal(err)
			}
			epb := len(b) - EPBSizeID(1)
			switch damage {
			case "block-type":
				binary.LittleEndian.PutUint32(b[epb:], blkIDB)
			case "short-epb":
				b = append(b[:epb], make([]byte, 12)...)
				binary.LittleEndian.PutUint32(b[epb:], blkEPB)
				binary.LittleEndian.PutUint32(b[epb+4:], 12)
				binary.LittleEndian.PutUint32(b[epb+8:], 12)
			case "caplen-size":
				binary.LittleEndian.PutUint32(b[epb+20:], 32)
			case "option-size":
				binary.LittleEndian.PutUint16(b[len(b)-18:], 4)
			case "option-end":
				binary.LittleEndian.PutUint32(b[len(b)-8:], 1)
			case "caplen":
				binary.LittleEndian.PutUint32(b[epb+20:], 65536)
			case "trailer":
				binary.LittleEndian.PutUint32(b[len(b)-4:], 0)
			case "unaligned":
				binary.LittleEndian.PutUint32(b[epb+4:], 49)
			case "oversize":
				binary.LittleEndian.PutUint32(b[epb+4:], 1<<21)
			case "truncated":
				b = b[:len(b)-1]
			case "header-only":
				// Keep a complete record followed by only the next block header.
				b = append(b, b[len(b)-EPBSizeID(1):len(b)-EPBSizeID(1)+8]...)
			case "interface":
				for off := 0; off < len(b); off += int(binary.LittleEndian.Uint32(b[off+4:])) {
					if binary.LittleEndian.Uint32(b[off:]) == blkEPB {
						binary.LittleEndian.PutUint32(b[off+8:], 7)
						break
					}
				}
			case "id":
				binary.LittleEndian.PutUint64(b[len(b)-16:], 0)
			case "option":
				binary.LittleEndian.PutUint16(b[len(b)-20:], 99)
			}
			if err := os.WriteFile(base+".cpu0", b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(base, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := MergeShardFiles(base, 1, cfg); err == nil {
				t.Fatal("accepted damaged shard")
			}
			if _, err := os.Stat(base + ".merging"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("merge temp remains: %v", err)
			}
			got, err := os.ReadFile(base)
			if err != nil || string(got) != "original" {
				t.Fatalf("published failed merge: %q %v", got, err)
			}
		})
	}
}

// These bytes were generated by the base commit 67dd943, before hook mode.
// Pin all three existing layouts so adding correlation cannot change them.
func TestHookModeLeavesLegacyBytes(t *testing.T) {
	t.Setenv("BPF_NINJA_FAST_PCAPNG", "1")
	for name, cfg := range map[string]Config{
		"entry": {},
		"exit":  {IsFexit: true, HookName: "xdp", Actions: []ActionName{{Value: 2, Name: "xdp:PASS"}}},
		"gated": {MultiPoint: true, HookName: "xdp", Actions: []ActionName{{Value: 2, Name: "xdp:PASS"}}},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.pcapng")
			w, err := NewWriter(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			p := capture.Packet{Timestamp: time.Unix(123, 456), Data: []byte{0xaa, 0xbb, 0xcc}, Action: 2, Mode: 0, PacketID: 1<<48 | 42}
			if err := w.Write(p); err != nil {
				t.Fatal(err)
			}
			p.Mode = 1
			p.Timestamp = p.Timestamp.Add(time.Nanosecond)
			if err := w.Write(p); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "legacy-"+name+".pcapng"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("legacy %s bytes changed\ngot=%x\nwant=%x", name, got, want)
			}
		})
	}
}

func TestHookMergeRejectsMixedLayouts(t *testing.T) {
	for _, hookFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("hookFirst=%v", hookFirst), func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "mixed.pcapng")
			for cpu := 0; cpu < 2; cpu++ {
				cfg := Config{}
				if (cpu == 0) == hookFirst {
					cfg.Hooks = []string{"hook_a"}
				}
				w, err := NewWriter(fmt.Sprintf("%s.cpu%d", base, cpu), cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := w.Write(capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{1}, SiteID: 1, PacketID: 1}); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(base, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := MergeShardFiles(base, 2, Config{}); err == nil || !strings.Contains(err.Error(), "legacy and hook") {
				t.Fatalf("mixed layouts: %v", err)
			}
			if got, err := os.ReadFile(base); err != nil || string(got) != "original" {
				t.Fatalf("published failed merge: %q %v", got, err)
			}
		})
	}
}

func TestHookLayoutErrorNamesShard(t *testing.T) {
	base := filepath.Join(t.TempDir(), "empty.pcapng")
	shard := base + ".cpu0"
	if err := os.WriteFile(shard, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	err := MergeShardFiles(base, 1, Config{})
	if !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), shard) {
		t.Fatalf("missing shard path or wrapped EOF: %v", err)
	}
	got, err := os.ReadFile(base)
	if err != nil || string(got) != "original" {
		t.Fatalf("published failed merge: %q %v", got, err)
	}
}

func TestHookMergeInterfaceTable(t *testing.T) {
	for _, detect := range []bool{false, true} {
		t.Run(fmt.Sprint(detect), func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "table.pcapng")
			for cpu, names := range [][]string{{"a"}, {"b"}} {
				w, err := NewWriter(fmt.Sprintf("%s.cpu%d", base, cpu), Config{Hooks: names})
				if err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			cfg := Config{Hooks: []string{"a"}}
			if detect {
				cfg = Config{}
			}
			if err := MergeShardFiles(base, 2, cfg); err == nil || !strings.Contains(err.Error(), base+".cpu1 interface table differs") {
				t.Fatalf("table mismatch: %v", err)
			}
		})
	}
}

func TestHookMergeRawAndMissing(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "raw.pcapng")
			w, err := NewWriter(base+".cpu0", Config{Hooks: []string{"a"}, LinkType: layers.LinkTypeRaw})
			if err != nil {
				t.Fatal(err)
			}
			if !empty {
				if err := w.Write(capture.Packet{Timestamp: time.Unix(1, 0), Data: []byte{0x45}, SiteID: 1, PacketID: 7}); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := MergeShardFiles(base, 2, Config{}); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(base)
			if err != nil {
				t.Fatal(err)
			}
			r, err := pcapgo.NewNgReader(bytes.NewReader(b), pcapgo.DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			intf, err := r.Interface(0)
			if err != nil || intf.LinkType != layers.LinkTypeRaw {
				t.Fatalf("interface: %+v %v", intf, err)
			}
			want := []uint64{7}
			if empty {
				want = nil
			}
			if got := epbPacketIDs(t, b); !slices.Equal(got, want) {
				t.Fatalf("ids=%v", got)
			}
		})
	}
}

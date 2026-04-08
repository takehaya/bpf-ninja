package program

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestCompileFilter(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"icmp", "icmp"},
		{"arp", "arp"},
		{"tcp port", "tcp port 80"},
		{"host", "host 10.0.0.1"},
		{"complex", "tcp port 80 and host 10.0.0.1"},
		{"vlan", "vlan 100"},
		{"udp", "udp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns, err := compileFilter(tt.expr)
			if err != nil {
				t.Fatalf("compileFilter(%q) failed: %v", tt.expr, err)
			}
			if len(insns) == 0 {
				t.Fatalf("compileFilter(%q) returned empty instructions", tt.expr)
			}
		})
	}
}

func TestCompileFilterInvalid(t *testing.T) {
	_, err := compileFilter("not a valid filter ???")
	if err == nil {
		t.Fatal("expected error for invalid filter, got nil")
	}
}

func TestBuildTracingInsns(t *testing.T) {
	tests := []struct {
		name    string
		filter  asm.Instructions
		isFexit bool
	}{
		{"entry_no_filter", nil, false},
		{"exit_no_filter", nil, true},
		{"entry_with_filter", dummyFilter(), false},
		{"exit_with_filter", dummyFilter(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// FD=0 は実際のmapではないが、命令生成のテストには十分
			insns := buildTracingInsns(tt.filter, nil, 0, 0, tt.isFexit)
			if len(insns) == 0 {
				t.Fatal("buildTracingInsns returned empty instructions")
			}

			// 最後の命令が Return であること
			last := insns[len(insns)-1]
			if last.OpCode != asm.Return().OpCode {
				t.Fatalf("last instruction is not Return: %v", last)
			}
		})
	}
}

func TestBuildTracingInsnsLabels(t *testing.T) {
	filter := dummyFilter()
	insns := buildTracingInsns(filter, nil, 0, 0, false)

	labels := map[string]bool{}
	for _, insn := range insns {
		if sym := insn.Symbol(); sym != "" {
			labels[sym] = true
		}
	}

	// "exit" ラベルは必ず存在する
	if !labels["exit"] {
		t.Error("missing 'exit' label")
	}

	// フィルタ付きなら "filter_result" と "len_ok" が存在する
	if !labels["filter_result"] {
		t.Error("missing 'filter_result' label")
	}
	if !labels["len_ok"] {
		t.Error("missing 'len_ok' label")
	}
}

// dummyFilter は最小限のフィルタ命令 (常にマッチ) を返す。
// cbpfc の出力をシミュレートする。
func dummyFilter() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R2, 1), // R2 = 1 (match)
	}
}

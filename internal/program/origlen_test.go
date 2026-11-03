package program

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

func sameIns(a, b asm.Instruction) bool {
	return a.OpCode == b.OpCode && a.Dst == b.Dst && a.Src == b.Src && a.Offset == b.Offset && a.Constant == b.Constant
}

// writesReg reports whether ins may write r (helper calls clobber only R0-R5).
func writesReg(ins asm.Instruction, r asm.Register) bool {
	switch cls := ins.OpCode.Class(); {
	case cls.IsALU(), cls == asm.LdXClass, cls == asm.LdClass:
		return ins.Dst == r
	case cls == asm.StXClass && ins.OpCode.Mode() != asm.MemMode: // atomics with fetch write Src
		return ins.Src == r
	}
	return false
}

// origLenFlow checks one built program: from the end of the packet prologue
// to the first instruction that saves or stores orig_len, nothing writes R8
// and every jump is forward (so the linear scan covers every path). After a
// gated fentry's stash at fp-72 nothing may write the slot before it is read
// back; after a gated fexit's save at hold+52 nothing may write it, and R8
// must be that hold when the exit record (exitRecord) reads it.
func origLenFlow(insns, prologue asm.Instructions, exitRecord bool) error {
	start := -1
	for i := 0; i+len(prologue) <= len(insns) && start < 0; i++ {
		match := true
		for j := range prologue {
			match = match && sameIns(insns[i+j], prologue[j])
		}
		if match {
			start = i + len(prologue)
		}
	}
	if start < 0 {
		return fmt.Errorf("prologue not found")
	}
	use := -1
	for i := start; i < len(insns) && use < 0; i++ {
		ins := insns[i]
		switch {
		case sameIns(ins, asm.Mov.Reg(asm.R1, asm.R8)) && i+1 < len(insns) && sameIns(insns[i+1], asm.StoreMem(asm.R0, 28, asm.R1, asm.Word)),
			sameIns(ins, asm.StoreMem(asm.R10, gatedOrigLenStash, asm.R8, asm.Word)),
			sameIns(ins, asm.StoreMem(asm.R0, holdExitLen, asm.R8, asm.Word)),
			sameIns(ins, asm.StoreMem(asm.R1, holdExitLen, asm.R8, asm.Word)):
			use = i
		}
	}
	if use < 0 {
		return fmt.Errorf("orig_len is never stored")
	}
	syms := map[string]int{}
	for i, ins := range insns {
		if s := ins.Symbol(); s != "" {
			syms[s] = i
		}
	}
	for i := start; i < use; i++ {
		ins := insns[i]
		if writesReg(ins, asm.R8) {
			return fmt.Errorf("insn %d writes R8 before orig_len is saved: %v", i, ins)
		}
		if op := ins.OpCode.JumpOp(); ins.OpCode.Class().IsJump() && op != asm.Call && op != asm.Exit {
			if j, ok := syms[ins.Reference()]; ins.Reference() != "" && (!ok || j <= i) || ins.Reference() == "" && ins.Offset < 0 {
				return fmt.Errorf("insn %d jumps backward: %v", i, ins)
			}
		}
	}
	saved := insns[use]
	switch {
	case saved.Dst == asm.R10:
		read := asm.LoadMem(asm.R1, asm.R10, gatedOrigLenStash, asm.Word)
		end, err := windowWrite(insns, use, asm.R10, gatedOrigLenStash, func(ins asm.Instruction) bool { return sameIns(ins, read) })
		if err == nil && end < 0 {
			err = fmt.Errorf("the stash is never read back")
		}
		return err
	case saved.Offset == holdExitLen:
		read := asm.LoadMem(asm.R1, asm.R8, holdExitLen, asm.Word)
		end, err := windowWrite(insns, use, saved.Dst, holdExitLen, func(ins asm.Instruction) bool { return sameIns(ins, read) })
		switch {
		case err != nil:
			return err
		case exitRecord && end < 0:
			return fmt.Errorf("the exit record does not read hold+%d", holdExitLen)
		case !exitRecord && end >= 0:
			return fmt.Errorf("no exit record expected, but hold+%d is read at %d", holdExitLen, end)
		}
	}
	return nil
}

// windowWrite follows the pointer base held at insns[from] (R10, or the hold
// slot a gated fexit stores through) up to the first insn done accepts, and
// fails on any write into the 4 bytes at off: a store through the pointer or
// a register derived from it (Mov, Add, a spill and fill; an Add of a
// register makes the offset unknown, which overlaps everything), or a helper
// given such a pointer (a probe read writes R2 bytes at R1, any other helper
// is assumed to write 8 bytes at each pointer argument). For the hold it also
// fails when done's insn reads through R8 while R8 is not the hold itself.
// It returns done's index, or -1 when no insn is accepted.
func windowWrite(insns asm.Instructions, from int, base asm.Register, off int, done func(asm.Instruction) bool) (int, error) {
	const unknown = -1 << 30
	overlaps := func(at, n int) bool { return at == unknown || at < off+4 && at+n > off }
	ptr := map[asm.Register]int{base: 0}      // registers pointing into base's memory
	frame := map[asm.Register]int{asm.R10: 0} // registers pointing into the stack
	spill := map[int]int{}                    // stack offset → spilled ptr offset
	if prev := insns[from-1]; base != asm.R10 && prev.OpCode == asm.LoadMemOp(asm.DWord) && prev.Dst == base && prev.Src == asm.R10 {
		spill[int(prev.Offset)] = 0 // the deferred fexit reloads its hold from this spill
	}
	clobberStack := func(at, n int) {
		for s := range spill {
			if at == unknown || s < at+n && s+8 > at {
				delete(spill, s)
			}
		}
	}
	size := 8
	for i := from + 1; i < len(insns); i++ {
		ins := insns[i]
		if done(ins) {
			if o, ok := ptr[asm.R8]; base != asm.R10 && (!ok || o != 0) {
				return -1, fmt.Errorf("insn %d reads the saved length while R8 is not the hold", i)
			}
			return i, nil
		}
		cls, n := ins.OpCode.Class(), ins.OpCode.Size().Sizeof()
		if cls.IsStore() {
			if o, ok := ptr[ins.Dst]; ok && overlaps(o+int(ins.Offset), n) {
				return -1, fmt.Errorf("insn %d stores over the saved length: %v", i, ins)
			}
			if o, ok := frame[ins.Dst]; ok {
				at := o + int(ins.Offset)
				if o == unknown {
					at = unknown
				}
				clobberStack(at, n)
				if p, ok := ptr[ins.Src]; ok && base != asm.R10 && cls == asm.StXClass && ins.OpCode.Mode() == asm.MemMode && n == 8 {
					spill[at] = p
				}
			}
		}
		switch {
		case ins.IsBuiltinCall():
			for r := asm.R1; r <= asm.R5; r++ {
				w := 8
				if ins.Constant == int64(asm.FnProbeReadKernel) {
					if r != asm.R1 {
						continue
					}
					w = size
				}
				if o, ok := ptr[r]; ok && overlaps(o, w) {
					return -1, fmt.Errorf("insn %d: helper may write the saved length through R%d", i, r)
				}
				if o, ok := frame[r]; ok {
					clobberStack(o, w)
				}
			}
			for r := asm.R0; r <= asm.R5; r++ {
				delete(ptr, r)
				delete(frame, r)
			}
		case ins.IsFunctionCall():
			return -1, fmt.Errorf("insn %d: BPF function call while the length is saved", i)
		case ins.OpCode == asm.LoadMemOp(asm.DWord) && func() bool { _, ok := frame[ins.Src]; return ok }():
			p, ok := spill[frame[ins.Src]+int(ins.Offset)]
			delete(ptr, ins.Dst)
			delete(frame, ins.Dst)
			if ok && frame[ins.Src] != unknown {
				ptr[ins.Dst] = p
			}
		case ins.OpCode == asm.Mov.Op(asm.RegSource):
			p, okp := ptr[ins.Src]
			f, okf := frame[ins.Src]
			delete(ptr, ins.Dst)
			delete(frame, ins.Dst)
			if okp {
				ptr[ins.Dst] = p
			}
			if okf {
				frame[ins.Dst] = f
			}
		case ins.OpCode.Class() == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Add:
			for _, m := range []map[asm.Register]int{ptr, frame} {
				p, ok := m[ins.Dst]
				_, src := m[ins.Src]
				switch {
				case ok && ins.OpCode.Source() == asm.ImmSource && p != unknown:
					m[ins.Dst] = p + int(ins.Constant)
				case ok || ins.OpCode.Source() == asm.RegSource && src:
					m[ins.Dst] = unknown
				}
			}
		default:
			for _, r := range []asm.Register{ins.Dst, ins.Src} {
				if writesReg(ins, r) && r != asm.R10 {
					delete(ptr, r)
					delete(frame, r)
				}
			}
			if ins.Dst == asm.R2 && ins.OpCode == asm.Mov.Op(asm.ImmSource) {
				size = int(ins.Constant)
			}
		}
	}
	return -1, nil
}

// TestOrigLenFlow runs origLenFlow over every builder that writes orig_len,
// at every hook (XDP, tc, cgroup-skb, netfilter, static XDP and tc): single-
// stage entry and exit, the --record filter and entry layouts, gated entry
// and exit for each --emit with and without the deferred prologue. Each is
// built with arg filters and an arg set, with and without the tag barrier,
// and with DSL packet sets of 4, 8, 10 and 16 key bytes (so the key zeroing,
// kunai's key writes and the set lookups sit inside the checked stretch); tc
// also with --tc-vlan-reinsert (the wire-frame copy). Libpcap builds also
// check a cBPF filter whose scratch reaches the gated stash at fp-72.
func TestOrigLenFlow(t *testing.T) {
	xdp, _ := hook.ByName(hook.KindXDP)
	type hookCase struct {
		h    *hook.Hook
		l3   bool // packet starts at L3
		vlan bool // try --tc-vlan-reinsert
	}
	hooks := map[string]hookCase{
		"xdp": {xdp, false, false}, "static-xdp-entry": {staticXDPHook(xdp, false), false, false}, "static-xdp-exit": {staticXDPHook(xdp, true), false, false},
	}
	if _, _, _, err := hook.SkBuffPacketOffsets(); err == nil {
		tc, _ := hook.ByName(hook.KindTC)
		cg, _ := hook.ByName(hook.KindCgroupSKB)
		hooks["tc"], hooks["cgroup-skb"], hooks["static-tc"] = hookCase{tc, false, true}, hookCase{cg, true, false}, hookCase{staticTCHook(tc, "f"), false, false}
		if nf, _ := hook.ByName(hook.KindNetfilter); nf != nil {
			if _, err := nf.PacketPrologue(); err == nil {
				hooks["netfilter"] = hookCase{nf, true, false}
			}
		}
	} else {
		t.Logf("kernel BTF not available, skb hooks not checked: %v", err)
	}

	u32 := &btf.Int{Name: "__u32", Size: 4}
	value := &btf.Struct{Name: "pol", Size: 4, Members: []btf.Member{{Name: "pol_rc", Type: u32}}}
	target := attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "value", Index: 2, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Const{Type: value}}},
	}}
	maps := testSetMaps(t, 77, 81, 82, 83, 84)
	tf := filter.TargetFilters{
		Args: []filter.ArgFilter{{ParamName: "value->pol_rc", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpGreaterEqual, Value: 3}},
		Sets: []filter.SetFilter{{Map: maps[0], KeySize: 4, StateOff: -1, TagWidth: 1,
			Fields: []filter.SetKeyField{{FieldName: "site", FieldSize: 4, ParamName: "site", ParamIdx: 1, ParamSize: 4}}}},
	}
	var layouts []*record.Layout
	for _, opt := range []recordbuild.Options{{Mode: record.ModeFilter}, {Mode: record.ModeEntry, MaxBytes: 64}} {
		l, err := recordbuild.Build(target, tf, opt)
		if err != nil || l == nil {
			t.Fatalf("layout %v: %+v %v", opt.Mode, l, err)
		}
		layouts = append(layouts, l)
	}
	tag := []setmap.KeyField{{Name: "tag", Size: 4}}
	set := func(name string, m *ebpf.Map, scalar bool, fields ...setmap.KeyField) *setmap.Set {
		var size uint32
		for _, f := range fields {
			size = max(size, f.Off+f.Size)
		}
		return &setmap.Set{SpecRef: setmap.SpecRef{Name: name}, Def: &setmap.Definition{Map: m, KeySize: size, IsScalar: scalar, Fields: fields, ValFields: tag}}
	}
	sets := []*setmap.Set{
		set("k", maps[1], true, setmap.KeyField{Name: "addr", Size: 4}),
		set("a", maps[2], false, setmap.KeyField{Name: "src", Size: 4}, setmap.KeyField{Name: "dst", Off: 4, Size: 4}),
		set("p", maps[3], true, setmap.KeyField{Name: "port", Size: 2}),
		set("sids", maps[4], true, setmap.KeyField{Name: "sid", Size: 16, IsBytes: true}),
	}
	exprs := []string{
		"ipv4[src in @k]/tcp",                         // 4 key bytes
		"ipv4[src in @a, dst in @a]/tcp",              // 8
		"ipv4[src in @a, dst in @a]/tcp[dport in @p]", // 10, two sets
		"ipv6[dst in @sids]",                          // 16
	}

	type filterCase struct {
		name  string
		out   [2]codegen.Output // entry, exit
		slots [2]*pktSetSlots
		tf    filter.TargetFilters
	}
	for hn, hc := range hooks {
		h := hc.h
		prologue, err := h.PacketPrologue()
		if err != nil {
			t.Fatalf("%s: %v", hn, err)
		}
		cases := []filterCase{{name: "args", tf: tf}}
		compile := func(name, expr string, vlan bool) {
			c := filterCase{name: name}
			for i, fexit := range []bool{false, true} {
				prev := TCVlanReinsert
				TCVlanReinsert = vlan
				c.slots[i] = newPktSetSlots(sets)
				out, err := compileFilterWithSlots(expr, true, fexit, h.ProgTypes[0], c.slots[i])
				TCVlanReinsert = prev
				if err != nil {
					t.Fatalf("%s %q: %v", hn, expr, err)
				}
				if vlan && !out.WireFrame {
					t.Fatalf("%s %q: --tc-vlan-reinsert did not select the wire-frame copy", hn, expr)
				}
				c.out[i] = out
			}
			cases = append(cases, c)
		}
		for _, e := range exprs {
			if !hc.l3 {
				e = "eth/" + e
			}
			compile(e, e, false)
		}
		if CBPFEnabled {
			c := filterCase{name: "cbpf-scratch", tf: tf}
			for i, fexit := range []bool{false, true} {
				out, err := compileFilter(cbpfDeepScratchFilter, false, fexit, h.ProgTypes[0])
				if err != nil {
					t.Fatal(err)
				}
				stashUsed := false
				for _, ins := range out.Main {
					stashUsed = stashUsed || ins.OpCode.Class().IsStore() && ins.Dst == asm.R10 && ins.Offset == gatedOrigLenStash
				}
				if !stashUsed {
					t.Fatal("cBPF filter does not exercise fp-72")
				}
				c.out[i] = out
			}
			cases = append(cases, c)
		}
		if hc.vlan {
			compile("vlan-reinsert", "eth/ipv4/tcp", true)
		}
		for _, c := range cases {
			for _, gateFD := range []int{0, 6} {
				name := fmt.Sprintf("%s/%s/gate=%d", hn, c.name, gateFD)
				check := func(what string, exitRecord bool, insns asm.Instructions, err error) {
					t.Helper()
					if err == nil {
						err = origLenFlow(insns, prologue, exitRecord)
					}
					if err == nil {
						err = wakeFlagFlow(insns) // the submit flag survives to every release
					}
					if err != nil {
						t.Errorf("%s/%s: %v", name, what, err)
					}
				}
				for i, fexit := range []bool{false, true} {
					refs := referencedSets(c.out[i].Extractions)
					insns, err := buildRecordingInsns(h, c.out[i], c.tf, 1, 2, 3, fexit, 48, c.slots[i], refs, gateFD, nil, 0, nil)
					check(fmt.Sprintf("tracing/fexit=%v", fexit), false, insns, err)
					for _, l := range layouts {
						var snap *fieldSnap
						if l.Mode == record.ModeFilter {
							snap = &fieldSnap{fd: 9, layout: l}
						}
						insns, err := buildRecordingInsns(h, c.out[i], c.tf, 1, 2, 3, fexit, 48, c.slots[i], refs, gateFD, l, 1, snap)
						check(fmt.Sprintf("record-%v/fexit=%v", l.Mode, fexit), false, insns, err)
					}
				}
				for _, emit := range []Emit{EmitBoth, EmitEntry, EmitExit} {
					insns, err := buildGatedEntryInsns(h, c.out[0], c.tf, 4, 5, 3, 2, c.slots[0], referencedSets(c.out[0].Extractions), emit, 128, gateFD)
					check(fmt.Sprintf("gated-entry/emit=%d", emit), false, insns, err)
					for _, deferred := range []bool{false, true} {
						insns, err := buildGatedExitInsns(h, c.out[1], c.tf, 1, 4, 3, 2, c.slots[1], referencedSets(c.out[1].Extractions), emit, 128, 48, gateFD, deferred)
						check(fmt.Sprintf("gated-exit/emit=%d/deferred=%v", emit, deferred), emit != EmitEntry, insns, err)
					}
				}
			}
		}
	}
}

// TestOrigLenPrologues evaluates each packet prologue symbolically: on exit
// R8 must hold the whole length (skb->len, or data_end - data at XDP) and
// R9 the window length (skb->len - skb->data_len at skb hooks).
func TestOrigLenPrologues(t *testing.T) {
	type prologueCase struct {
		h      *hook.Hook
		r8, r9 string
		loads  map[int16]string // LdX offset (member, or stack slot when stack) → field
		stack  bool
	}
	xdp, _ := hook.ByName(hook.KindXDP)
	cases := map[string]prologueCase{
		"xdp":        {xdp, "end-data", "end-data", map[int16]string{0: "data", 8: "end"}, false},
		"static-xdp": {staticXDPHook(xdp, false), "end-data", "end-data", map[int16]string{-160: "data", -152: "end"}, true},
	}
	if data, length, dataLen, err := hook.SkBuffPacketOffsets(); err == nil {
		skb := map[int16]string{int16(data): "data", int16(length): "len", int16(dataLen): "data_len"}
		for _, k := range []hook.Kind{hook.KindTC, hook.KindCgroupSKB, hook.KindNetfilter} {
			h, _ := hook.ByName(k)
			cases[string(k)] = prologueCase{h, "len", "len-data_len", skb, false}
		}
		tc, _ := hook.ByName(hook.KindTC)
		cases["static-tc"] = prologueCase{staticTCHook(tc, "f"), "len", "len-data_len", map[int16]string{-160: "data", -152: "len", -148: "data_len"}, true}
	} else {
		t.Logf("kernel BTF not available, skb hooks not checked: %v", err)
	}
	for name, c := range cases {
		insns, err := c.h.PacketPrologue()
		if err != nil {
			t.Logf("%s: %v", name, err) // netfilter needs bpf_nf_ctx (6.4+)
			continue
		}
		val := map[asm.Register]string{}
		for _, ins := range insns {
			switch {
			case ins.OpCode.Class() == asm.LdXClass && (ins.Src == asm.R10) == c.stack && ins.Src != asm.R1:
				val[ins.Dst] = c.loads[ins.Offset]
			case ins.OpCode == asm.Mov.Op(asm.RegSource):
				val[ins.Dst] = val[ins.Src]
			case ins.OpCode == asm.Sub.Op(asm.RegSource):
				val[ins.Dst] = val[ins.Dst] + "-" + val[ins.Src]
			case ins.OpCode == asm.Add.Op(asm.RegSource) && val[ins.Dst] == "data_len" && val[ins.Src] == "len-data_len":
				val[ins.Dst] = "len"
			case writesReg(ins, ins.Dst):
				val[ins.Dst] = "?"
			}
		}
		if val[asm.R8] != c.r8 || val[asm.R9] != c.r9 {
			t.Errorf("%s: R8=%q R9=%q, want %q and %q", name, val[asm.R8], val[asm.R9], c.r8, c.r9)
		}
	}
}

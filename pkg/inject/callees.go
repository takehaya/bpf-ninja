package inject

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Callee is one helper or kernel function a program calls, outside the map
// helpers and bpf_tail_call, which have their own kinds. Typed means the call
// table has a row for it, so its hook is typed; a rule's Calls may name every
// callee without a Reason, which says why the callee gets no hook. Module is the fd_array offset of a module
// kernel function, zero for vmlinux. Sites are its call sites' raw PCs.
type Callee struct {
	Name   string
	Kind   string // "helper" or "kfunc"
	Module int16
	Ret    CalleeRet // "" when unknown
	Typed  bool
	Sites  []uint32
	Reason string
}

// FuncRange is a BTF function and its raw instruction slots [Start, End).
type FuncRange struct {
	Name       string
	Start, End uint32
}

// CallDiscovery lists every helper and kernel-function call of one program
// beside its map calls: Sites are the HookCall sites in PC order, a site of a
// callee with a row carrying the transform's Reason and CtxSource, any other
// site its callee's Reason (a helper without a row that may be hooked counts
// as a callee with a row); TailCalls are the bpf_tail_call sites. Labels names
// every site of the full discovery, map calls included, by PC (see SiteLabels),
// and Fingerprint identifies the listing (see ListingFingerprint).
type CallDiscovery struct {
	Sites       []LookupSite
	TailCalls   []LookupSite
	Callees     []Callee
	Funcs       []FuncRange
	Labels      map[uint32]string
	Fingerprint string
}

// noHookForm is the Reason of a kernel function the call table has no row for.
const noHookForm = "no hook form yet"

// DiscoverCallSitesRaw lists the helper, kernel-function and tail-call sites of
// p and labels them together with mapCalls, the program's DiscoverMapCallsRaw.
// p.Kernel and p.Modules name kernel-function calls; without them such a call
// is listed unnamed. It performs no syscalls and changes nothing the
// transform does.
func DiscoverCallSitesRaw(p RawProgram, mapCalls []LookupSite) (CallDiscovery, error) {
	insns, _, resolve, err := prepareRawLookup(p)
	if err != nil {
		return CallDiscovery{}, err
	}
	// The sites of callees with a row, with the reasons a rule naming them would see.
	known, err := discoverSites(insns, p.Type, resolve, LookupRequest{Calls: slices.Concat(SupportedCalls(), hookableHelpers()), Kernel: p.Kernel, Modules: p.Modules})
	if err != nil {
		return CallDiscovery{}, err
	}
	rows := map[uint32]LookupSite{}
	for _, site := range known {
		if site.Op == HookCall {
			rows[site.SitePC] = site.LookupSite
		}
	}
	var d CallDiscovery
	callees := map[string]int{}
	var funcName, file string
	var line uint32
	it := insns.Iterate()
	for it.Next() {
		pc, ins := uint32(it.Offset), it.Ins
		if fn := btf.FuncMetadata(ins); fn != nil {
			funcName, file, line = fn.Name, "", 0
			if n := len(d.Funcs); n != 0 {
				d.Funcs[n-1].End = pc
			}
			d.Funcs = append(d.Funcs, FuncRange{Name: fn.Name, Start: pc})
		}
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		if !ins.IsBuiltinCall() && !ins.IsKfuncCall() {
			continue
		}
		site := LookupSite{Op: HookCall, FuncName: funcName, File: file, Line: line, SitePC: pc, InstructionIndex: it.Index}
		if ins.IsBuiltinCall() {
			if _, ok := mapCallOps[asm.BuiltinFunc(ins.Constant)]; ok {
				continue
			}
			if asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
				site.Op = HookTailCall
				d.TailCalls = append(d.TailCalls, site)
				continue
			}
		}
		c := calleeOf(ins, p.Kernel, p.Modules)
		if row, ok := rows[pc]; ok {
			site = row
		} else {
			site.Reason = c.Reason
		}
		site.Call = c.Name
		i, ok := callees[c.Kind+"\x00"+c.Name]
		if !ok {
			i = len(d.Callees)
			callees[c.Kind+"\x00"+c.Name] = i
			d.Callees = append(d.Callees, c)
		}
		d.Callees[i].Sites = append(d.Callees[i].Sites, pc)
		d.Sites = append(d.Sites, site)
	}
	if n := len(d.Funcs); n != 0 {
		d.Funcs[n-1].End = uint32(insns.Size() / asm.InstructionSize)
	}
	all := slices.Concat(mapCalls, d.Sites, d.TailCalls)
	d.Labels = SiteLabels(d.Funcs, all)
	d.Fingerprint, err = ListingFingerprint(p, d.Funcs, d.Labels, all)
	return d, err
}

// calleeOf describes the callee of a helper or kernel-function call, without sites.
func calleeOf(ins *asm.Instruction, kernel *btf.Spec, modules map[int16]*btf.Spec) Callee {
	row, name, named := callee(ins, kernel, modules)
	c := Callee{Kind: "kfunc", Name: name, Module: kfuncModule(ins), Typed: row != nil}
	if ins.IsBuiltinCall() {
		c.Kind = "helper"
		h, ok := helperByID(ins.Constant)
		if !ok {
			c.Name = fmt.Sprintf("helper_%d", ins.Constant)
			c.Reason = fmt.Sprintf("helper id %d is past the helper table", ins.Constant)
			return c
		}
		c.Name, c.Ret = h.Name, h.Ret
		_, c.Reason = helperCall(asm.BuiltinFunc(ins.Constant))
		return c
	} else if named {
		c.Ret = kfuncRet(ins, kernel, modules)
	}
	switch {
	case !named:
		c.Reason = "a kernel-function call that cannot be named"
	case row != nil:
	case denyReason(c.Name) != "":
		c.Reason = denyReason(c.Name)
	case c.Ret == RetVoid:
		c.Reason = "returns nothing"
	case c.Ret == RetUnsupported:
		c.Reason = "not a callable helper"
	default:
		c.Reason = noHookForm
	}
	return c
}

// kfuncRet is the result kind of a raw kernel-function call's BTF prototype,
// modifiers and typedefs skipped: an integer or enum is a scalar, any pointer
// a pointer, none void; "" when the prototype cannot be read.
func kfuncRet(ins *asm.Instruction, kernel *btf.Spec, modules map[int16]*btf.Spec) CalleeRet {
	spec := kernel
	if ins.Offset != 0 {
		spec = modules[ins.Offset]
	}
	if spec == nil || ins.Reference() != "" {
		return ""
	}
	typ, err := spec.TypeByID(btf.TypeID(ins.Constant))
	fn, ok := typ.(*btf.Func)
	if err != nil || !ok {
		return ""
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return ""
	}
	switch btf.UnderlyingType(proto.Return).(type) {
	case *btf.Void:
		return RetVoid
	case *btf.Pointer:
		return RetPointer
	case *btf.Int, *btf.Enum:
		return RetScalar
	}
	if proto.Return == nil {
		return RetVoid
	}
	return ""
}

// denyReason says why a callee is never hooked by name, or "".
func denyReason(name string) string {
	has := func(prefix string) bool { return strings.HasPrefix(name, prefix) }
	switch {
	case name == "bpf_spin_lock" || name == "bpf_spin_unlock" || has("bpf_res_spin_lock") || has("bpf_res_spin_unlock") ||
		name == "bpf_preempt_disable" || name == "bpf_preempt_enable" || name == "bpf_rcu_read_lock" || name == "bpf_rcu_read_unlock" ||
		name == "bpf_local_irq_save" || name == "bpf_local_irq_restore":
		return "takes or releases a lock or a critical section"
	case slices.Contains([]string{"bpf_for_each_map_elem", "bpf_loop", "bpf_find_vma", "bpf_user_ringbuf_drain", "bpf_timer_set_callback",
		"bpf_rbtree_add_impl", "bpf_wq_set_callback", "bpf_wq_set_callback_impl", "bpf_task_work_schedule_signal",
		"bpf_task_work_schedule_signal_impl", "bpf_task_work_schedule_resume", "bpf_task_work_schedule_resume_impl"}, name):
		return "runs or registers a callback"
	case name == "bpf_throw":
		return "does not return"
	case slices.Contains([]string{"bpf_get_stack", "bpf_get_stackid", "bpf_get_task_stack", "bpf_get_branch_snapshot", "bpf_get_func_ip"}, name):
		return "reads native code addresses or branch records, which inserted code may change"
	case has("bpf_iter_") && (strings.HasSuffix(name, "_new") || strings.HasSuffix(name, "_next") || strings.HasSuffix(name, "_destroy")):
		return "an iterator: the verifier forks and prunes loop states at its next"
	case has("bpf_list_") || has("bpf_rbtree_") || name == "bpf_refcount_acquire_impl" || has("bpf_stream_") ||
		has("bpf_arena_") && strings.HasSuffix(name, "_pages"):
		return "the verifier lets it run with a lock held"
	case slices.Contains([]string{"bpf_obj_new_impl", "bpf_percpu_obj_new_impl", "bpf_obj_drop_impl", "bpf_percpu_obj_drop_impl"}, name):
		return "the verifier inserts arguments at the call"
	case name == "bpf_cast_to_kern_ctx" || name == "bpf_rdonly_cast":
		return "the verifier rewrites the call to a register move"
	case name == "bpf_session_cookie" || name == "bpf_session_is_return" || name == "__bpf_trap":
		return "the verifier inlines or refuses the call"
	}
	return ""
}

// SiteLabels names every site by PC: NAME@FUNC:LINE, or NAME@FUNC+SLOT
// without line info, where SLOT is the site's slot offset from its function's
// first instruction. NAME is the map of a lookup (any when known only at run
// time), MAP.OP for another map call, the callee of a call and tail_call for
// a tail call. Sites sharing a label get #2, #3 in PC order. Labels are
// computed over the full discovery, so a listing and a later selection agree.
func SiteLabels(funcs []FuncRange, sites []LookupSite) map[uint32]string {
	sites = slices.SortedFunc(slices.Values(sites), func(a, b LookupSite) int { return cmp.Compare(a.SitePC, b.SitePC) })
	labels := make(map[uint32]string, len(sites))
	seen := map[string]int{}
	for _, site := range sites {
		name := cmp.Or(site.MapName, "any")
		switch {
		case site.Op == HookCall:
			name = site.Call
		case site.Op == HookTailCall:
			name = "tail_call"
		case site.Op != HookLookup:
			name += "." + string(site.Op)
		}
		label := fmt.Sprintf("%s@%s:%d", name, site.FuncName, site.Line)
		if site.Line == 0 {
			start := uint32(0)
			for _, f := range funcs {
				if f.Start <= site.SitePC && site.SitePC < f.End {
					start = f.Start
				}
			}
			label = fmt.Sprintf("%s@%s+%d", name, site.FuncName, site.SitePC-start)
		}
		seen[label]++
		if n := seen[label]; n > 1 {
			label += fmt.Sprintf("#%d", n)
		}
		labels[site.SitePC] = label
	}
	return labels
}

// ListingFingerprint identifies the program a listing was made from:
// "sha256:" and the hex SHA-256 over the instructions as the loader passed
// them, with the fd immediate of every map reference by fd (BPF_PSEUDO_MAP_FD
// and BPF_PSEUDO_MAP_VALUE) zeroed and the value offset kept; the name and
// type of each map reference; the label, PC, kind, name, function, file and
// line of every site; and the BTF function names with their slot ranges.
// Loader-side relocations that differ per load (kfunc BTF ids, ksym
// addresses, CO-RE) change it.
func ListingFingerprint(p RawProgram, funcs []FuncRange, labels map[uint32]string, sites []LookupSite) (string, error) {
	insns := slices.Clone(p.Instructions)
	h := sha256.New()
	var refs bytes.Buffer
	for i := range insns {
		ins := &insns[i]
		if ins.OpCode != asm.LoadImmOp(asm.DWord) || (ins.Src != asm.PseudoMapFD && ins.Src != asm.PseudoMapValue) {
			continue
		}
		m := p.Maps[int32(ins.Constant)]
		fmt.Fprintf(&refs, "map %q %d\n", m.Name, m.Type)
		ins.Constant &^= 0xffffffff
	}
	if err := insns.Marshal(h, rawByteOrder()); err != nil {
		return "", err
	}
	h.Write(refs.Bytes())
	sites = slices.SortedFunc(slices.Values(sites), func(a, b LookupSite) int { return cmp.Compare(a.SitePC, b.SitePC) })
	for _, site := range sites {
		_, _ = fmt.Fprintf(h, "site %q %d %s %q %q %q %d\n", labels[site.SitePC], site.SitePC, site.Op,
			cmp.Or(site.Call, site.MapName), site.FuncName, site.File, site.Line)
	}
	for _, f := range funcs {
		_, _ = fmt.Fprintf(h, "func %q %d %d\n", f.Name, f.Start, f.End)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

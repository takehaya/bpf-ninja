package inject

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// callHookName is the hook of the Calls callee name.
func callHookName(req LookupRequest, name string) string { return req.HookName + "_" + name }

// callReason gives the reason a call site cannot be hooked by its own
// position: an original call right before or after it, or the start of its
// function. The validators cut the code between two original calls into
// windows only when nothing is inserted there, and code inserted before a
// call that starts its function cannot be told from the function's prologue.
func callReason(insns asm.Instructions, i int) string {
	isCall := func(j int) bool {
		return j >= 0 && j < len(insns) && insns[j].OpCode.Class().IsJump() && insns[j].OpCode.JumpOp() == asm.Call
	}
	switch {
	case isCall(i-1) || isCall(i+1):
		return "call: the instruction before or after the call is a call"
	case i == 0 || btf.FuncMetadata(&insns[i]) != nil:
		return "call: the call is the first instruction of its function"
	}
	return ""
}

// selectCalls groups the call sites, one hook PREFIX_<callee> per callee, in
// the order of each callee's first site. Sites are fitted one by one: a site
// that cannot be hooked is skipped with its reason, whatever Auto is, and
// never costs another site its hook.
func selectCalls(sites []discoveredLookup, req LookupRequest, types *btf.Spec) ([]lookupGroup, []LookupSite) {
	var groups []lookupGroup
	var skipped []LookupSite
	skip := func(site discoveredLookup, reason string) {
		s := site.LookupSite
		if reason != "" {
			s.Reason = reason
		}
		skipped = append(skipped, s)
	}
	byName := map[string]int{}
	for _, site := range sites {
		if site.Reason != "" || site.noFloor {
			skip(site, "")
			continue
		}
		if slots := lookupSlots(req.Stack.floor(site.FuncName)); req.Stack.perFrame() && slots.result < -siteFrameLimit(req.Stack) {
			skip(site, fmt.Sprintf("call: the hook's slots do not fit below function %q stack floor %d", site.FuncName, req.Stack.floor(site.FuncName)))
			continue
		}
		i, ok := byName[site.Call]
		if !ok {
			i = len(groups)
			byName[site.Call] = i
			groups = append(groups, lookupGroup{name: callHookName(req, site.Call), op: HookCall, call: site.row})
		}
		groups[i].sites = append(groups[i].sites, site)
	}
	var kept []lookupGroup
	for _, group := range groups {
		row := group.call
		if !validIdent(group.name) {
			skipped = skipGroup(skipped, group, fmt.Sprintf("hook name %q is longer than %d bytes", group.name, MaxHookName))
			continue
		}
		if row.ArgReg != 0 {
			sizes := []uint32{}
			typed := !row.RetPtr && row.Writes
			for _, site := range group.sites {
				if !slices.Contains(sizes, site.argSize) {
					sizes = append(sizes, site.argSize)
				}
				typed = typed && site.argOwn
			}
			if len(sizes) > 1 {
				skipped = skipGroup(skipped, group, fmt.Sprintf("call: %s is called with more than one argument size in this program (%d and %d)", row.Name, sizes[0], sizes[1]))
				continue
			}
			group.argSize, group.typed = sizes[0], typed
			group.argType, group.argName = callArgType(row, sizes[0], types, req.Kernel)
		}
		kept = append(kept, group)
	}
	return kept, skipped
}

// callHook generates the hook of a call group (shape S, M or P) and its plan
// entry. A typed hook takes const T *arg; an untyped one takes const void *arg
// tagged arg:untrusted with its size, or with StaticUntrusted keeps the typed
// prototype and an empty body. A pointer result is always untyped.
func callHook(group lookupGroup, ctx btf.Type, req LookupRequest) (asm.Instructions, LookupHook) {
	row := group.call
	plan := LookupHook{Name: group.name, Kind: HookCall, When: string(CallAny), SiteArg: true, Sites: publicLookupSites(group.sites),
		Call: row.Name, RetPtr: row.RetPtr}
	if row.ArgReg == 0 {
		return pointerHook(group.name, ctx, nil, true, false, "ret"), plan
	}
	plan.ArgReg, plan.ArgType, plan.ArgSize = int(row.ArgReg), group.argName, group.argSize
	ptrs := []btf.FuncParam{{Name: "arg", Type: group.argType}}
	var scalars []string
	if row.RetPtr {
		ptrs = append(ptrs, btf.FuncParam{Name: "ret", Type: &btf.Void{}})
	} else {
		scalars = []string{"ret"}
	}
	if group.typed {
		return pointerHook(group.name, ctx, ptrs, true, false, scalars...), plan
	}
	if req.StaticUntrusted {
		plan.Static = true
		return staticHook(pointerHook(group.name, ctx, ptrs, true, false, scalars...)), plan
	}
	plan.Untrusted = true
	hook := pointerHook(group.name, ctx, ptrs, true, true, scalars...)
	if size := taggedSize(group.argType, group.argSize); size > 0 {
		fn := btf.FuncMetadata(&hook[0])
		fn.Tags = append(fn.Tags, hookabi.SizeTag("arg", size))
	}
	return hook, plan
}

// callAfter calls a call site's hook right after the callee and restores R0
// (sequences A and B): the result slot keeps R0 across the hook, ctx comes
// from the ctx slot, and the argument from the key slot the prelude filled.
func callAfter(pc uint32, call siteCall, slots lookupLayout) asm.Instructions {
	result := int16(slots.result)
	out := asm.Instructions{
		asm.StoreMem(asm.RFP, result, asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, int16(slots.ctx), asm.DWord),
		asm.Mov.Imm32(asm.R2, int32(pc)),
	}
	if call.argReg != 0 {
		out = append(out, asm.LoadMem(asm.R3, asm.RFP, int16(slots.key), asm.DWord), asm.Mov.Reg(asm.R4, asm.R0))
	} else {
		out = append(out, asm.Mov.Reg(asm.R3, asm.R0))
	}
	return append(out, asm.Call.Label(call.hook), asm.LoadMem(asm.R0, asm.RFP, result, asm.DWord))
}

// dropCalls removes every call group, listing its sites as skipped with
// reason. Call sites are the newest kind, so they go first when a limit of
// the spliced program breaks.
func dropCalls(groups []lookupGroup, skipped []LookupSite, reason string) ([]lookupGroup, []LookupSite, bool) {
	var kept []lookupGroup
	for _, group := range groups {
		if group.op == HookCall {
			skipped = skipGroup(skipped, group, reason)
			continue
		}
		kept = append(kept, group)
	}
	return kept, skipped, len(kept) != len(groups)
}

// funcCount counts the functions of insns.
func funcCount(insns asm.Instructions) int {
	n := 0
	for i := range insns {
		if btf.FuncMetadata(&insns[i]) != nil {
			n++
		}
	}
	return n
}

// maxFuncs is the kernel's limit on the functions of one program
// (BPF_MAX_SUBPROGS).
const maxFuncs = 256

// regName is r as the rule texts spell it, such as r3.
func regName(r asm.Register) string { return strings.ToLower(r.String()) }

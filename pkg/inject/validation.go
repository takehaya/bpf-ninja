package inject

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

var ErrCheckerNotApplicable = errors.New("checker not applicable")

// BuildLookupTargets builds the checker's trusted target binding from the
// rewrite plan and generated hook symbols, never from transformed call targets.
func BuildLookupTargets(out asm.Instructions, hooks []LookupHook) ([]injectcheck.SiteTarget, error) {
	for i, ins := range out {
		if ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() == asm.Call && ins.OpCode.Source() == asm.RegSource {
			return nil, fmt.Errorf("%w: cannot pair indirect callx at instruction %d", ErrCheckerNotApplicable, i)
		}
	}
	wanted := map[string]bool{}
	for _, hook := range hooks {
		wanted[hook.Name] = true
	}
	starts := map[string]int{}
	for i, ins := range out {
		name := ins.Symbol()
		if !wanted[name] {
			continue
		}
		if _, exists := starts[name]; exists {
			return nil, fmt.Errorf("inject: duplicate generated hook symbol %q", name)
		}
		starts[name] = i
	}
	for name := range wanted {
		if _, ok := starts[name]; !ok {
			return nil, fmt.Errorf("inject: generated hook symbol %q not found", name)
		}
	}

	targets := make([]injectcheck.SiteTarget, 0)
	type targetKey struct {
		site int
		when injectcheck.TargetWhen
	}
	seen := map[targetKey]bool{}
	add := func(site int, when injectcheck.TargetWhen, hook int, ctx *injectcheck.CtxSource) error {
		key := targetKey{site, when}
		if seen[key] {
			return fmt.Errorf("inject: duplicate target site=%d when=%s", site, when)
		}
		seen[key] = true
		targets = append(targets, injectcheck.SiteTarget{Site: site, When: when, Hook: hook, Ctx: ctx})
		return nil
	}
	ctxSource := func(site LookupSite) (*injectcheck.CtxSource, error) {
		switch {
		case site.CtxSource == "" || site.CtxSource == "entry":
			return nil, nil
		case len(site.CtxSource) == 2 && site.CtxSource[0] == 'r':
			reg, err := strconv.Atoi(site.CtxSource[1:])
			if err == nil && reg >= int(asm.R6) && reg <= int(asm.R9) {
				return &injectcheck.CtxSource{Reg: reg}, nil
			}
		case strings.HasPrefix(site.CtxSource, "fp-"):
			off, err := strconv.ParseInt(site.CtxSource[2:], 10, 16)
			if err == nil && off <= -8 && off >= -512 && off%8 == 0 {
				return &injectcheck.CtxSource{Slot: int16(off)}, nil
			}
		}
		return nil, fmt.Errorf("inject: invalid context source %q at site %d", site.CtxSource, site.InstructionIndex)
	}
	for _, hook := range hooks {
		when := injectcheck.TargetWhen(hook.When)
		switch {
		case hook.Kind == HookEntry || hook.Kind == HookTailCall:
			when = injectcheck.TargetAny
		case hook.Kind == HookLookup && when == "":
			when = injectcheck.TargetHit
		case hook.Kind == HookLookup && (when == injectcheck.TargetHit || when == injectcheck.TargetMiss || when == injectcheck.TargetAny):
		case hook.Kind != HookLookup && (when == injectcheck.TargetError || when == injectcheck.TargetAny):
		default:
			return nil, fmt.Errorf("inject: invalid target condition %q for %s hook %q", hook.When, hook.Kind, hook.Name)
		}
		if hook.Kind == HookEntry {
			if err := add(-1, when, starts[hook.Name], nil); err != nil {
				return nil, err
			}
			continue
		}
		for _, site := range hook.Sites {
			ctx, err := ctxSource(site)
			if err != nil {
				return nil, err
			}
			if err := add(site.InstructionIndex, when, starts[hook.Name], ctx); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Site != targets[j].Site {
			return targets[i].Site < targets[j].Site
		}
		return targets[i].When < targets[j].When
	})
	return targets, nil
}

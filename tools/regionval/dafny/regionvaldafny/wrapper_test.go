package regionvaldafny

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// ins encodes one instruction in wire format (RFC 9669 section 3).
func ins(op byte, dst, src byte, off int16, imm int32) []byte {
	b := make([]byte, 8)
	b[0] = op
	b[1] = dst&0xf | src<<4
	binary.LittleEndian.PutUint16(b[2:], uint16(off))
	binary.LittleEndian.PutUint32(b[4:], uint32(imm))
	return b
}

func cat(xs ...[]byte) []byte {
	var out []byte
	for _, x := range xs {
		out = append(out, x...)
	}
	return out
}

var (
	helper   = func() []byte { return ins(0x85, 0, 0, 0, 1) }
	hookCall = func() []byte { return ins(0x85, 0, 1, 0, 40) }
	stxdw    = func(base, src byte, off int16) []byte { return ins(0x7b, base, src, off, 0) }
	ldxdw    = func(dst, base byte, off int16) []byte { return ins(0x79, dst, base, off, 0) }
	movr     = func(dst, src byte) []byte { return ins(0xbf, dst, src, 0, 0) }
	movk     = func(dst byte, k int32) []byte { return ins(0xb7, dst, 0, 0, k) }
	addk     = func(dst byte, k int32) []byte { return ins(0x07, dst, 0, 0, k) }
	jeqk     = func(dst byte, k int32, off int16) []byte { return ins(0x15, dst, 0, off, k) }
	ja       = func(off int16) []byte { return ins(0x05, 0, 0, off, 0) }
	exit     = func() []byte { return ins(0x95, 0, 0, 0, 0) }
)

const floor = -168

// A site window in the shape of P2 with a guard: helper, save r0 below the
// floor, skip the hook if r0 == 0, hook(r1 = &slot), restore r0.
func siteWindow() []byte {
	return cat(
		helper(),           // 0
		stxdw(10, 0, -176), // 1
		jeqk(0, 0, 3),      // 2 -> 6
		movr(1, 10),        // 3
		addk(1, -176),      // 4
		hookCall(),         // 5
		ldxdw(0, 10, -176), // 6
	)
}

func replace(w []byte, pc int, with ...[]byte) []byte {
	return cat(w[:8*pc], cat(with...), w[8*pc+8:])
}

func insert(w []byte, pc int, with ...[]byte) []byte {
	return cat(w[:8*pc], cat(with...), w[8*pc:])
}

func TestValidWindows(t *testing.T) {
	cases := []struct {
		name string
		w    []byte
		sp   Spec
	}{
		{"site", siteWindow(), SiteSpec(floor)},
		{"site-no-hook", cat(helper(), stxdw(10, 0, -176), ldxdw(0, 10, -176)), SiteSpec(floor)},
		{"site-bare-helper", helper(), SiteSpec(floor)},
		{"tail-site", cat(helper(), movr(1, 10), addk(1, -176), hookCall()), TailSiteSpec(floor)},
		{"entry-prologue", stxdw(10, 1, -176), EntryPrologueSpec(floor)},
		{"callback-prologue", ldxdw(0, 6, 8), CallbackPrologueSpec(floor)},
		{"pass-load", ldxdw(3, 10, -176), PassSpec(floor, 3)},
		{"hook-body", cat(jeqk(1, 0, 1), ldxdw(2, 1, 0), movk(0, 0), exit()), HookBodySpec()},
		{"empty", nil, SiteSpec(floor)},
	}
	for _, c := range cases {
		if c.name == "empty" {
			// no helper call on the only path: a site window must contain it
			if v := Validate(c.w, c.sp); v.Validated {
				t.Errorf("%s: validated", c.name)
			}
			continue
		}
		if v := Validate(c.w, c.sp); !v.Validated {
			t.Errorf("%s: not validated at pc %d: %s", c.name, v.PC, v.Reason)
		}
	}
}

// Planted faults that are expressible on a single window.  Every one
// must be NotValidated.
func TestPlantings(t *testing.T) {
	w := siteWindow()
	S := SiteSpec(floor)
	cases := []struct {
		name string
		w    []byte
		sp   Spec
	}{
		{"C1 store at floor", replace(w, 1, stxdw(10, 0, -168)), S},
		{"C1 store straddles floor", replace(w, 1, stxdw(10, 0, -172)), S},
		{"C1 base r9", replace(w, 1, stxdw(9, 0, -176)), S},
		{"C1 below -512", replace(w, 1, stxdw(10, 0, -520)), S},
		{"C2 r6 = r0", insert(w, 6, movr(6, 0)), S},
		{"C2 r9 += 1", insert(w, 1, addk(9, 1)), S},
		{"C3 st above floor (ST not allowlisted)", insert(w, 1, ins(0x7a, 10, 0, -8, 0)), S},
		{"C3 stx above floor", insert(w, 1, stxdw(10, 1, -8)), S},
		{"C6 add reg (not allowlisted)", insert(w, 4, ins(0x0f, 1, 3, 0, 0)), S},
		{"C4 backward guard", replace(w, 2, jeqk(0, 0, -1)), S},
		{"C4 guard past window", replace(w, 2, jeqk(0, 0, 5)), S},
		{"C4 ja past window", insert(w, 3, ja(5)), S},
		{"C5 second hook call", insert(w, 6, hookCall()), S},
		{"C5 second helper call", insert(w, 1, helper()), S},
		{"C5 hook call in prologue", cat(stxdw(10, 1, -176), hookCall()), EntryPrologueSpec(floor)},
		{"C6 atomic add", insert(w, 1, ins(0xdb, 10, 0, -176, 0)), S},
		{"C6 xor32", insert(w, 1, ins(0xac, 3, 3, 0, 0)), S},
		{"C6 unknown opcode", insert(w, 1, ins(0xff, 0, 0, 0, 0)), S},
		{"C6 callx", insert(w, 1, ins(0x8d, 2, 0, 0, 0)), S},
		{"C6 ld_imm64", insert(w, 1, ins(0x18, 3, 0, 0, 0), ins(0, 0, 0, 0, 0)), S},
		{"C6 kfunc call", insert(w, 1, ins(0x85, 0, 2, 0, 7)), S},
		{"C6 reserved field", replace(w, 3, ins(0xbf, 1, 10, 1, 0)), S},
		{"C6 write r10", insert(w, 1, movk(10, 0)), S},
		{"r0 restore removed", w[:6*8], S},
		{"r0 restore width w", replace(w, 6, ins(0x61, 0, 10, -176, 0)), S},
		{"r0 restore offset f-16", replace(w, 6, ldxdw(0, 10, -184)), S},
		{"r0 restore skipped after the hook", insert(w, 6, ja(1)), S},
		{"r0 restore skipped on one arm", insert(w, 6, jeqk(3, 0, 1)), S},
		{"site r2 = r10 before helper", insert(w, 0, movr(2, 10)), S},
		{"P1 ld r1 removed then r1 clobbered", cat(stxdw(10, 1, -176), movk(1, 0)), EntryPrologueSpec(floor)},
		{"P1b write r2", ldxdw(2, 6, 8), CallbackPrologueSpec(floor)},
		{"P9 write other reg", ldxdw(4, 10, -176), PassSpec(floor, 3)},
		{"P7 store", cat(stxdw(10, 1, -8), movk(0, 0), exit()), HookBodySpec()},
		{"P7 call", cat(hookCall(), movk(0, 0), exit()), HookBodySpec()},
		{"P7 backward jump", cat(movk(0, 0), jeqk(1, 0, -2), exit()), HookBodySpec()},
		{"P7 r0 = 0 removed", cat(ldxdw(2, 1, 0), exit()), HookBodySpec()},
		{"P7 falls through", movk(0, 0), HookBodySpec()},
		{"P7 clobbers r6", cat(ldxdw(6, 1, 0), movk(0, 0), exit()), HookBodySpec()},
		{"exit in site window", insert(w, 6, exit()), S},
		{"model-load: site loads r10+0", insert(w, 6, ldxdw(3, 10, 0)), S},
		{"bad spec floor", w, CustomSpec(8, nil, true, true, true, true, true, false)},
		{"bad spec free r6", w, CustomSpec(floor, []int{6}, true, true, true, true, true, false)},
		{"length not multiple of 8", w[:13], S},
	}
	for _, c := range cases {
		if v := Validate(c.w, c.sp); v.Validated {
			t.Errorf("%s: validated (expected NotValidated)", c.name)
		}
	}
}

// Every one of the 256 opcodes, inserted alone (other fields zero) into the
// site window: anything outside the allowlist must not validate.
func TestOpcodeSweep(t *testing.T) {
	allowed := map[byte]bool{}
	for _, cls := range []byte{0x04, 0x07} {
		for _, code := range []byte{0x00, 0x40, 0x50, 0x60, 0xb0} {
			allowed[cls|code] = true // K source
		}
		for _, code := range []byte{0x40, 0x50, 0xb0} {
			allowed[cls|code|0x08] = true // X source: or, and, mov only
		}
	}
	for _, op := range []byte{0x61, 0x69, 0x71, 0x79, 0x63, 0x6b, 0x73, 0x7b, 0x05, 0x15, 0x55, 0x76, 0x85, 0x95} {
		allowed[op] = true
	}
	w := siteWindow()
	for op := 0; op < 256; op++ {
		v := Validate(insert(w, 1, ins(byte(op), 0, 0, 0, 0)), SiteSpec(floor))
		if v.Validated && !allowed[byte(op)] {
			t.Errorf("opcode %#02x outside the allowlist validated", op)
		}
	}
}

func randState(r *rand.Rand) ([NRegs]uint64, [Stack]byte) {
	var regs [NRegs]uint64
	var st [Stack]byte
	pick := []uint64{0, 1, ^uint64(0), 1 << 63, 0xffffffff, 0x80000000}
	for i := range regs {
		if r.Intn(3) == 0 {
			regs[i] = pick[r.Intn(len(pick))]
		} else {
			regs[i] = r.Uint64()
		}
	}
	r.Read(st[:])
	return regs, st
}

func randOracle(r *rand.Rand) []uint64 {
	o := make([]uint64, 6+512+8)
	for i := range o {
		if r.Intn(4) == 0 {
			o[i] = 0
		} else {
			o[i] = r.Uint64()
		}
	}
	return o
}

// The theorem, tested: for validated windows the obligation predicate holds
// on random runs.  (A sanity check of the statement, not of the proof.)
func TestValidatedRunsSatisfyObligations(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	wins := []struct {
		w  []byte
		sp Spec
	}{
		{siteWindow(), SiteSpec(floor)},
		{cat(jeqk(1, 0, 1), ldxdw(2, 1, 0), movk(0, 0), exit()), HookBodySpec()},
		{stxdw(10, 1, -176), EntryPrologueSpec(floor)},
	}
	for _, x := range wins {
		if !Validate(x.w, x.sp).Validated {
			t.Fatal("window not validated")
		}
		for i := 0; i < 200; i++ {
			regs, st := randState(r)
			_, _, ok := RunAndCheck(x.w, x.sp, regs, st, randOracle(r))
			if !ok {
				t.Fatalf("obligations violated on a validated window (iteration %d)", i)
			}
		}
	}
}

// The plantings are real violations: some run breaks the obligations.
func TestPlantingsAreRealViolations(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	w := siteWindow()
	bad := map[string][]byte{
		"restore removed":   w[:6*8],
		"store above floor": replace(w, 1, stxdw(10, 0, -16)),
		"r6 = r0":           insert(w, 6, movr(6, 0)),
	}
	for name, b := range bad {
		found := false
		for i := 0; i < 50 && !found; i++ {
			regs, st := randState(r)
			_, _, ok := RunAndCheck(b, SiteSpec(floor), regs, st, randOracle(r))
			found = !ok
		}
		if !found {
			t.Errorf("%s: no violating run found", name)
		}
	}
}

// Reference-interpreter spot checks against hand-computed values.
func TestConcreteStep(t *testing.T) {
	var regs [NRegs]uint64
	regs[10] = 0x10000
	regs[3] = 0xffffffff_00000005
	s := InitState(regs, [Stack]byte{})
	step := func(b []byte) State {
		s.PC = 0
		n, k := ConcreteStep(b, floor, s, nil)
		if k != StepNext {
			t.Fatalf("step %x: kind %d", b, k)
		}
		return n
	}
	if got := step(ins(0x07, 3, 0, 0, -1)).Regs[3]; got != 0xffffffff_00000004 { // add64 imm sign-extended
		t.Errorf("add64: %#x", got)
	}
	if got := step(ins(0x04, 3, 0, 0, -1)).Regs[3]; got != 4 { // add32 zero-extends
		t.Errorf("add32: %#x", got)
	}
	if got := step(ins(0xbc, 4, 3, 0, 0)).Regs[4]; got != 5 { // mov32 reg
		t.Errorf("mov32: %#x", got)
	}
	if got := step(ins(0x67, 3, 0, 0, 4)).Regs[3]; got != 0xfffffff0_00000050 { // lsh64
		t.Errorf("lsh64: %#x", got)
	}
	if got := step(ins(0x64, 3, 0, 0, 4)).Regs[3]; got != 0x50 { // lsh32
		t.Errorf("lsh32: %#x", got)
	}
	// store then load through the frame, little-endian
	s = step(stxdw(10, 3, -16))
	if s.Stack[512-16] != 0x05 || s.Stack[512-9] != 0xff {
		t.Errorf("stxdw bytes: % x", s.Stack[512-16:512-8])
	}
	if got := step(ins(0x61, 5, 10, -16, 0)).Regs[5]; got != 5 { // ldxw
		t.Errorf("ldxw: %#x", got)
	}
	// jsge32: w3 = 5 >= 0 -> taken
	s.PC = 0
	n, _ := ConcreteStep(cat(ins(0x76, 3, 0, 2, 0), exit(), exit(), exit()), floor, s, nil)
	if n.PC != 3 {
		t.Errorf("jsge32 pc %d", n.PC)
	}
	// undecodable -> stuck
	if _, k := ConcreteStep(ins(0xff, 0, 0, 0, 0), floor, s, nil); k != StepStuck {
		t.Errorf("0xff not stuck")
	}
}

// ---------------- P8 wrapper sites ----------------

var (
	callW  = func() []byte { return ins(0x85, 0, 1, 0, 7) } // BPF_PSEUDO_CALL to W
	lookup = func() []byte { return ins(0x85, 0, 0, 0, 1) } // map_lookup_elem (does not read r4)
	other  = func() []byte { return ins(0x85, 0, 0, 0, 2) } // map_update_elem (reads r4)
)

// WP sets r4; W calls O[i] behind a guard on r4 and returns its result.
func p8() (wp, w, oi []byte) {
	wp = cat(movk(4, 3), callW())
	w = cat(jeqk(4, 0, 1), movk(4, 1), lookup(), exit())
	return wp, w, lookup()
}

func TestP8(t *testing.T) {
	wp, w, oi := p8()
	if v := Validate(wp, WrapSiteSpec(floor, w, oi)); !v.Validated {
		t.Fatalf("P8 window not validated at pc %d: %s", v.PC, v.Reason)
	}
	ok := []struct {
		name   string
		wp, w  []byte
		helper []byte
	}{
		{"bare call W", callW(), cat(lookup(), exit()), lookup()},
		{"W saves r0 in r6 and moves it back", callW(), cat(lookup(), movr(6, 0), movr(0, 6), exit()), lookup()},
		{"W hook after the helper", callW(), cat(lookup(), movr(6, 0), hookCall(), movr(0, 6), exit()), lookup()},
		{"non-lookup, r4 untouched", callW(), cat(other(), exit()), other()},
		{"W loads through r1", callW(), cat(ldxdw(6, 1, 0), lookup(), exit()), lookup()},
	}
	for _, c := range ok {
		if v := Validate(c.wp, WrapSiteSpec(floor, c.w, c.helper)); !v.Validated {
			t.Errorf("%s: not validated at pc %d: %s", c.name, v.PC, v.Reason)
		}
	}
	bad := []struct {
		name   string
		wp, w  []byte
		helper []byte
	}{
		{"P8-shape: call W not last", cat(callW(), movk(4, 0)), w, oi},
		{"P8-shape: no call W", movk(4, 3), w, oi},
		{"P8-helper-id: O[i] differs", wp, w, other()},
		{"P8-helper-id: O[i] not a helper call", wp, w, hookCall()},
		{"P8-helper-other: second helper id in W (unreachable)", wp, cat(lookup(), exit(), other()), oi},
		{"P8-helper-other: two copies of O[i] on two arms", wp, cat(jeqk(4, 0, 2), lookup(), exit(), lookup(), exit()), oi},
		{"P8-r10: W reads r10", wp, cat(movr(1, 10), lookup(), exit()), oi},
		{"P8-r10: W loads via r10", wp, cat(ldxdw(6, 10, -8), lookup(), exit()), oi},
		{"P8-store: W stores", wp, cat(stxdw(1, 2, 0), lookup(), exit()), oi},
		{"P8-wpstore: WP stores", cat(stxdw(10, 1, -176), callW()), w, oi},
		{"P8-wp-writes: WP writes r1", cat(movk(1, 0), callW()), w, oi},
		{"P8-wp-writes: WP writes and restores r2", cat(movr(6, 2), movr(2, 6), callW()), w, oi},
		{"P8-wp-writes: WP hook call", cat(hookCall(), callW()), w, oi},
		{"P8-wp-writes: WP helper call", cat(lookup(), callW()), w, oi},
		{"P8-once: WP jumps over call W", cat(jeqk(1, 0, 1), callW()), w, oi},
		{"P8-once: W path without helper", wp, cat(jeqk(1, 0, 1), lookup(), exit()), oi},
		{"P8-once: helper twice", wp, cat(lookup(), lookup(), exit()), oi},
		{"R15: W changes r1", wp, cat(movk(1, 0), lookup(), exit()), oi},
		{"R15: non-lookup with r4 changed", movk(4, 3), cat(other(), exit()), other()},
		{"R15: non-lookup, WP changed r4", cat(movk(4, 3), callW()), cat(other(), exit()), other()},
		{"P8-ret: W clobbers r0", wp, cat(lookup(), movk(0, 0), exit()), oi},
		{"P8-ret: W falls off its end", wp, lookup(), oi},
		{"W changes r6 (C2 of the caller is kept anyway; r6 of W is free)", wp, cat(lookup(), movk(6, 0), exit()), oi},
		{"W jumps backward", wp, cat(lookup(), jeqk(0, 0, -2), exit()), oi},
		{"W two hook calls", wp, cat(lookup(), movr(6, 0), hookCall(), hookCall(), movr(0, 6), exit()), oi},
		{"W undecodable", wp, cat(lookup(), ins(0xff, 0, 0, 0, 0), exit()), oi},
		{"model-load: WP loads r10+0 (above the frame)", cat(ldxdw(4, 10, 0), callW()), w, oi},
		{"model-load: WP loads r10-520 (below the frame)", cat(ldxdw(4, 10, -520), callW()), w, oi},
	}
	for _, c := range bad {
		v := Validate(c.wp, WrapSiteSpec(floor, c.w, c.helper))
		if c.name == "W changes r6 (C2 of the caller is kept anyway; r6 of W is free)" {
			// W's r6..r9 are its own (calling convention); the caller's r6..r9 come back on return.
			if !v.Validated {
				t.Errorf("%s: not validated: %s", c.name, v.Reason)
			}
			continue
		}
		if v.Validated {
			t.Errorf("%s: validated (expected NotValidated)", c.name)
		}
	}
}

func p8Oracle(r *rand.Rand) []uint64 {
	return append(randOracle(r), randOracle(r)[:32]...)
}

// The theorem, tested on P8: validated windows satisfy the obligations on
// random runs, and every run reaches the window end through W's EXIT.
func TestP8RunsSatisfyObligations(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	wp, w, oi := p8()
	wins := []struct{ wp, w, oi []byte }{
		{wp, w, oi},
		{callW(), cat(lookup(), movr(6, 0), hookCall(), movr(0, 6), exit()), lookup()},
		{callW(), cat(ldxdw(6, 1, 0), lookup(), exit()), lookup()},
	}
	for _, x := range wins {
		sp := WrapSiteSpec(floor, x.w, x.oi)
		if !Validate(x.wp, sp).Validated {
			t.Fatal("window not validated")
		}
		for i := 0; i < 200; i++ {
			regs, st := randState(r)
			fin, k, ok := RunAndCheck(x.wp, sp, regs, st, p8Oracle(r))
			if !ok || k != Done {
				t.Fatalf("obligations violated on a validated P8 window (iteration %d, outcome %d)", i, k)
			}
			last := fin.Events[len(fin.Events)-1]
			if last.Kind != EvRet || fin.Regs[0] != last.Ret || fin.PC != len(x.wp)/8 {
				t.Fatalf("P8 run does not end with the return from W: %+v", last.Kind)
			}
		}
	}
	// plantings are real violations
	bad := map[string]struct{ wp, w, oi []byte }{
		"W clobbers r0":   {wp, cat(lookup(), movk(0, 0), exit()), oi},
		"W changes r1":    {wp, cat(movk(1, 0), lookup(), exit()), oi},
		"WP writes r1":    {cat(movk(1, 0), callW()), w, oi},
		"W stores":        {wp, cat(stxdw(1, 2, 0), lookup(), exit()), oi},
		"jump over W":     {cat(jeqk(1, 0, 1), callW()), w, oi},
		"helper id wrong": {wp, w, other()},
	}
	for name, b := range bad {
		found := false
		for i := 0; i < 100 && !found; i++ {
			regs, st := randState(r)
			if name == "jump over W" {
				regs[1] = 0
			}
			_, _, ok := RunAndCheck(b.wp, WrapSiteSpec(floor, b.w, b.oi), regs, st, p8Oracle(r))
			found = !ok
		}
		if !found {
			t.Errorf("%s: no violating run found", name)
		}
	}
}

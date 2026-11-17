#!/usr/bin/env python3
"""Hand-built capture pairs for call sites that are not map lookups.

Writes tools/regionval/testdata/export/callsite/*.json in the capture format
regionval reads (README.md, Capture files). The pairs are built by hand from
raw instruction bytes and a minimal BTF with two FUNCs (prog and hook); no
compiler, kernel or bpf-ninja code is involved, and nothing is loaded. Each rewritten program has an
entry prologue that saves ctx and one site around a call (a helper or a
kfunc) with one of the two inserted sequences:

  result only:   call C; *(r10+res)=r0; r1=*(r10+ctx); w2=pc; r3=r0; call H; r0=*(r10+res)
  arg + result:  *(r10+key)=rN; call C; *(r10+res)=r0; r1=*(r10+ctx); w2=pc;
                 r3=*(r10+key); r4=r0; call H; r0=*(r10+res)

Usage: python3 -I tools/regionval/testdata/mkcaptures.py

TestCallSites (export_test.go) holds the rule each pair must be rejected by.
"""
import json
import os
import struct
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export", "callsite")


def ins(op, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


def mov(d, s): return ins(0xbf, d, s)
def movi(d, k): return ins(0xb7, d, 0, 0, k)
def movw(d, k): return ins(0xb4, d, 0, 0, k)
def addi(d, k): return ins(0x07, d, 0, 0, k)
def stx(off, s): return ins(0x7b, 10, s, off)
def ldx(d, off): return ins(0x79, d, 10, off)
def helper(i): return ins(0x85, 0, 0, 0, i)
def kfunc(btf_id, off=0): return ins(0x85, 0, 2, off, btf_id)
EXIT = ins(0x95)
HOOK = "hook"  # marker: call to the hook function


def btf(funcs):
    """funcs: [(name, [param names])]; FUNC ids are 3, 5, ... in order."""
    strs = b"\0"

    def s(x):
        nonlocal strs
        o = len(strs)
        strs += x.encode() + b"\0"
        return o
    types = struct.pack("<III", s("u64"), 1 << 24, 8) + struct.pack("<I", 64)  # 1: INT u64
    ids = {}
    tid = 2
    for name, params in funcs:
        types += struct.pack("<III", 0, (13 << 24) | len(params), 1)  # FUNC_PROTO -> u64
        for p in params:
            types += struct.pack("<II", s(p), 1)
        types += struct.pack("<III", s(name), (12 << 24) | 1, tid)  # FUNC, global
        ids[name] = tid + 1
        tid += 2
    hdr = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strs))
    return (hdr + types + strs).hex(), ids


def capture(name, orig, trans, hook_body, floor, note, expect):
    """orig: original instructions; trans: list of ('o', insn) | ('i', insn) | ('i', HOOK)."""
    hook_start = len(trans)
    t, kappa = [], []
    oi = 0
    for j, (k, x) in enumerate(trans):
        if x == HOOK:
            x = ins(0x85, 0, 1, 0, hook_start - j - 1)
        if k in ("o", "O"):  # "O": stands where O[oi] was but differs (planted)
            if k == "o" and x != orig[oi]:
                sys.exit(f"{name}: T[{j}] is not O[{oi}]")
            kappa.append(j)
            oi += 1
        t.append(x)
    if oi != len(orig):
        sys.exit(f"{name}: {oi} of {len(orig)} originals placed")
    t += hook_body
    blob, ids = btf([("prog", ["ctx"]), ("hook", ["ctx", "site", "key", "value"])])
    fi = lambda recs: b"".join(struct.pack("<II", a, b) for a, b in recs).hex()
    c = {
        "format": 1, "kernel": "none", "program": note, "func": "prog", "prog_type": 6,
        "original_insns_hex": b"".join(orig).hex(),
        "original_func_info_hex": fi([(0, ids["prog"])]),
        "transformed_insns_hex": b"".join(t).hex(),
        "transformed_func_info_hex": fi([(0, ids["prog"]), (hook_start, ids["hook"])]),
        "transformed_btf_hex": blob,
        "floors": [{"name": "prog", "start": 0, "floor": floor, "source": "fixture"}],
        "hints": {"certificate": {"original": kappa}, "units": "decoded instruction indices (ld_imm64 counts once)"},
        "mutation": {"set": "callsite", "id": name, "fixture": "tools/regionval/testdata/mkcaptures.py", "expect": expect},
    }
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(c, f, indent=1)
        f.write("\n")


HOOK_BODY = [movi(0, 0), EXIT]


def result_only(name, callee, expect, note, post=(), fault=None):
    """O: r6 = r1; call C; post; exit.  Slots: ctx -8, result -16; floor 0."""
    orig = [mov(6, 1), callee, *post, EXIT]
    trans = [("i", stx(-8, 1)), ("o", mov(6, 1))]
    trans += [("o", callee), ("i", stx(-16, 0)), ("i", ldx(1, -8)), ("i", movw(2, 1)),
              ("i", mov(3, 0)), ("i", HOOK)]
    if fault != "noR0":  # noR0: r0 is left as the hook returned it
        trans += [("i", ldx(0, -16))]
    trans += [("o", x) for x in post] + [("o", EXIT)]
    capture(name, orig, trans, HOOK_BODY, 0, note, expect)


def arg_result(name, callee, expect, note, fault=None, reg=2):
    """O: r6 = r1; r2 = r10 - 64; r3 = 64; r4 = 0; r1 = r6; call C; exit.
    Slots: ctx -72, key -80, result -88; floor -64."""
    res = -56 if fault == "C1" else -88
    orig = [mov(6, 1), mov(2, 10), addi(2, -64), movi(3, 64), movi(4, 0), mov(1, 6), callee, EXIT]
    pro = [("i", stx(-72, 1))]
    if fault == "C5-other":  # a kfunc call in the entry prologue, away from any centre
        pro += [("i", kfunc(70000)), ("i", ldx(1, -72))]
    trans = pro + [("o", x) for x in orig[:6]]
    trans += [("i", stx(-80, reg))]
    if fault == "R15":  # the saved argument register is changed before the call
        trans += [("i", addi(reg, 8))]
    centre = callee
    if fault == "kappa":  # the centre is a different kfunc id than O's
        centre = ins(0x85, 0, 2, struct.unpack("<h", callee[2:4])[0], struct.unpack("<i", callee[4:])[0] + 1)
        trans += [("O", centre)]
    else:
        trans += [("o", callee)]
    if fault == "twice":  # the original call again, right after the centre
        trans += [("i", callee)]
    trans += [("i", stx(res, 0)), ("i", ldx(1, -72)), ("i", movw(2, 6)), ("i", ldx(3, -80)),
              ("i", mov(4, 0)), ("i", HOOK)]
    if fault == "C2":
        trans += [("i", movi(6, 0))]
    trans += [("i", movi(0, 0) if fault == "R0" else ldx(0, res)), ("o", EXIT)]
    body = HOOK_BODY if fault != "P7" else [stx(-8, 1), movi(0, 0), EXIT]
    capture(name, orig, trans, body, -64, note, expect)


def main():
    os.makedirs(OUT, exist_ok=True)
    # Step 2: helper sites that are not map lookups.
    result_only("clean-helper-result", helper(5), "validated",
                "bpf_ktime_get_ns (helper 5), result-only sequence")
    arg_result("clean-helper-arg", helper(69), "validated",
               "bpf_fib_lookup (helper 69), r2 saved, arg+result sequence")
    # Step 3: kfunc sites.  BTF id 1 collides with bpf_map_lookup_elem as a
    # helper id: a kfunc centre must get no lookup binds.
    result_only("clean-kfunc-result", kfunc(60001), "validated",
                "kfunc BTF id 60001 (vmlinux, off 0), result-only sequence")
    # BTF id 12 is bpf_tail_call's helper id: the centre reaches the cores as
    # the tail call and rule site refuses the window by its kind.
    result_only("PL-kfunc-imm12-site", kfunc(12), "site",
                "kfunc BTF id 12, result-only sequence without the r0 reload", fault="noR0")
    arg_result("clean-kfunc-arg", kfunc(1, 1), "validated",
               "kfunc BTF id 1 in module BTF fd index 1 (off 1), r2 saved, arg+result sequence")
    # The run between a helper and a following kfunc stays the helper's postlude.
    result_only("clean-helper-then-kfunc", helper(5), "validated",
                "helper 5 site whose postlude is followed by an original kfunc call", post=[kfunc(60001)])
    for fault, rule in [("R0", "R0"), ("R15", "R15"), ("twice", "C5"), ("C1", "C1"), ("P7", "P7"),
                        ("C2", "C2"), ("kappa", "struct:kappa"), ("C5-other", "C5")]:
        arg_result("PL-kfunc-" + fault, kfunc(1, 1), rule, f"clean-kfunc-arg with planted fault {fault}", fault=fault)


if __name__ == "__main__":
    main()

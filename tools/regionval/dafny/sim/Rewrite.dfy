// The rewrite M(P): P' laid out from P and the inserted pieces of the ten
// forms P1, P1b, P1c, P2 (with MF), P3, P4, P5, P7, P8, P9, and the windows the region validator
// checks, with the Spec each window kind gets (dafny/contract Spec).
//
// The layout is the checker's decomposition S1-S3 (and S9) made into a
// function: a P' that the checker accepts is Layout(P, D) for the
// decomposition D it found.  Inserted code is kept as wire bytes, exactly
// as the validator receives it.
include "Model.dfy"

module SimRewrite {
  import opened Bits
  import S = Semantics
  import opened Obligations
  import Api
  import Checker
  import opened SimModel

  // ---------------- the inserted pieces ----------------

  datatype FPKind = FP1b | FP9                       // callback prologue, pass prologue
  datatype FProl = FProl(kind: FPKind, code: seq<bv8>)
  // P1c-P5 and MF: prelude B(i) and postlude post(i) of a site helper or
  // tail call; binds: the record-binding obligations the validator also
  // checked (irrelevant to preservation).
  datatype Site = Site(pre: seq<bv8>, post: seq<bv8>, binds: seq<Bind>)
  datatype PassLoad = PassLoad(reg: nat, code: seq<bv8>)         // P9: PL(i), writes r_G = reg
  datatype Wrap = Wrap(wp: seq<bv8>, body: seq<bv8>, binds: seq<Bind>)  // P8: WP(i) and W_i's bytes
  datatype InsFn = HookFn(body: seq<bv8>) | WrapFn(site: nat)   // P7 hook, P8 wrapper

  // pro0: P1 entry prologue (empty: none).  fp: function prologues by
  // function start.  pl: pass loads by call index.  site, wrap: by helper
  // index.  fns(i): inserted functions placed just before instruction i;
  // tail: inserted functions after the last original instruction.
  datatype Decomp = Decomp(pro0: seq<bv8>, fp: map<nat, FProl>, pl: map<nat, PassLoad>,
                           site: map<nat, Site>, wrap: map<nat, Wrap>,
                           fns: map<nat, seq<InsFn>>, tail: seq<InsFn>)

  function NI(b: seq<bv8>): nat { |b| / 8 }

  // ---------------- lengths and positions ----------------

  function FnLen(D: Decomp, g: InsFn): nat {
    match g
    case HookFn(b) => NI(b)
    case WrapFn(s) => if s in D.wrap then NI(D.wrap[s].body) else 0
  }
  function FnsLen(D: Decomp, gs: seq<InsFn>): nat decreases |gs| {
    if |gs| == 0 then 0 else FnLen(D, gs[0]) + FnsLen(D, gs[1..])
  }
  function FnsAt(D: Decomp, i: nat): seq<InsFn> { if i in D.fns then D.fns[i] else [] }
  function FPLen(D: Decomp, i: nat): nat { if i in D.fp then NI(D.fp[i].code) else 0 }
  function PLLen(D: Decomp, i: nat): nat { if i in D.pl then NI(D.pl[i].code) else 0 }
  function PreLen(D: Decomp, i: nat): nat {
    if i in D.wrap then NI(D.wrap[i].wp) else if i in D.site then NI(D.site[i].pre) else 0
  }
  function PostLen(D: Decomp, i: nat): nat { if i in D.site && i !in D.wrap then NI(D.site[i].post) else 0 }
  function BlockLen(D: Decomp, i: nat): nat {
    FnsLen(D, FnsAt(D, i)) + FPLen(D, i) + PLLen(D, i) + PreLen(D, i) + 1 + PostLen(D, i)
  }

  // Start of the block of instruction i (i = n: the trailing functions).
  function Start(D: Decomp, i: nat): nat decreases i {
    if i == 0 then NI(D.pro0) else Start(D, i - 1) + BlockLen(D, i - 1)
  }
  // e(i): the entry point of i (head of PL(i) B(i) WP(i) kappa(i)).
  function E(D: Decomp, i: nat): nat { Start(D, i) + FnsLen(D, FnsAt(D, i)) + FPLen(D, i) }
  // fe(G): the head of FP(G), or e(G) if it is empty.
  function FE(D: Decomp, g: nat): nat { Start(D, g) + FnsLen(D, FnsAt(D, g)) }
  // kappa(i): the position of I_i (or of call W_i).
  function K(D: Decomp, i: nat): nat { E(D, i) + PLLen(D, i) + PreLen(D, i) }

  // Every inserted function with its entry position.
  function FnStarts(D: Decomp, gs: seq<InsFn>, base: nat): seq<(InsFn, nat)> decreases |gs| {
    if |gs| == 0 then [] else [(gs[0], base)] + FnStarts(D, gs[1..], base + FnLen(D, gs[0]))
  }
  function AllFnsFrom(D: Decomp, n: nat, i: nat): seq<(InsFn, nat)> decreases n - i {
    if i >= n then FnStarts(D, D.tail, Start(D, n))
    else FnStarts(D, FnsAt(D, i), Start(D, i)) + AllFnsFrom(D, n, i + 1)
  }
  function AllFns(P: seq<OInstr>, D: Decomp): seq<(InsFn, nat)> { AllFnsFrom(D, |P|, 0) }

  ghost function Hooks(P: seq<OInstr>, D: Decomp): set<nat> {
    set k | 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k].0.HookFn? :: AllFns(P, D)[k].1
  }
  // Entry of W_s (its first placement; S9 requires exactly one).
  function WStartIn(fs: seq<(InsFn, nat)>, s: nat): nat decreases |fs| {
    if |fs| == 0 then 0 else if fs[0].0 == WrapFn(s) then fs[0].1 else WStartIn(fs[1..], s)
  }
  function WStart(P: seq<OInstr>, D: Decomp, s: nat): nat { WStartIn(AllFns(P, D), s) }

  // ---------------- encodings ----------------

  function B4(v: int): seq<bv8> {
    var u := (v % 0x1_0000_0000) as bv64;
    [ByteOf(u, 0), ByteOf(u, 1), ByteOf(u, 2), ByteOf(u, 3)]
  }
  // call helper id: opcode 0x85, src 0, imm = id (little-endian).
  function EncHelper(id: bv32): seq<bv8> { [0x85, 0, 0, 0] + BytesOf(id as bv64, 4) }
  // BPF_PSEUDO_CALL with relative offset imm: opcode 0x85, src 1.
  function EncCallLocal(imm: int): seq<bv8> { [0x85, 0x10, 0, 0] + B4(imm) }
  // The central helper as the validator sees it (empty for a non-site).
  function Enc(ins: OInstr): seq<bv8> {
    match ins
    case Hcall(false, id) => EncHelper(id)
    case Tail => EncHelper(12)
    case _ => []
  }

  // ---------------- the code of P' ----------------

  function Slice(b: seq<bv8>, k: nat): seq<bv8> requires 8 * k + 8 <= |b| { b[8 * k .. 8 * k + 8] }
  function Ns(b: seq<bv8>): seq<TI> {
    seq(NI(b), k requires 0 <= k < NI(b) => N(Slice(b, k)))
  }

  // W_s: its bytes, with each helper call being the original I_s.
  function WCode(P: seq<OInstr>, D: Decomp, s: nat): seq<TI> {
    if s !in D.wrap || s >= |P| then []
    else
      var b := D.wrap[s].body;
      seq(NI(b), k requires 0 <= k < NI(b) =>
        if S.Decode(Slice(b, k)).Some? && S.Decode(Slice(b, k)).value.CallHelper? then O(P[s], s) else N(Slice(b, k)))
  }
  function FnCode(P: seq<OInstr>, D: Decomp, g: InsFn): seq<TI> {
    match g
    case HookFn(b) => Ns(b)
    case WrapFn(s) => WCode(P, D, s)
  }
  function FnsCode(P: seq<OInstr>, D: Decomp, gs: seq<InsFn>): seq<TI> decreases |gs| {
    if |gs| == 0 then [] else FnCode(P, D, gs[0]) + FnsCode(P, D, gs[1..])
  }

  // S3: branches to t go to e(t); calls to G go to fe(G).
  function Reloc(D: Decomp, ins: OInstr): OInstr {
    match ins
    case Jcc(code, srcs, t) => Jcc(code, srcs, E(D, t))
    case Ja(t) => Ja(E(D, t))
    case MayGoto(t) => MayGoto(E(D, t))
    case Call(t) => Call(FE(D, t))
    case _ => ins
  }

  // S1: kappa(i) holds I_i relocated, or call W_i at a wrapped site.
  function KappaTI(P: seq<OInstr>, D: Decomp, i: nat): TI requires i < |P| {
    if i in D.wrap then N(EncCallLocal(WStart(P, D, i) - K(D, i) - 1)) else O(Reloc(D, P[i]), i)
  }

  function Opt<T>(m: map<nat, T>, i: nat, f: T -> seq<bv8>): seq<bv8> { if i in m then f(m[i]) else [] }

  // S2: the order of the pieces between kappa(i-1) and kappa(i).
  opaque function Block(P: seq<OInstr>, D: Decomp, i: nat): seq<TI> requires i < |P| {
    FnsCode(P, D, FnsAt(D, i))
    + Ns(Opt(D.fp, i, (p: FProl) => p.code))
    + Ns(Opt(D.pl, i, (p: PassLoad) => p.code))
    + (if i in D.wrap then Ns(D.wrap[i].wp) else Ns(Opt(D.site, i, (s: Site) => s.pre)))
    + [KappaTI(P, D, i)]
    + (if i in D.wrap then [] else Ns(Opt(D.site, i, (s: Site) => s.post)))
  }
  function Blocks(P: seq<OInstr>, D: Decomp, i: nat): seq<TI> requires i <= |P| decreases |P| - i {
    if i == |P| then [] else Block(P, D, i) + Blocks(P, D, i + 1)
  }

  opaque ghost function Layout(P: seq<OInstr>, D: Decomp): RwProg {
    RwProg(Ns(D.pro0) + Blocks(P, D, 0) + FnsCode(P, D, D.tail),
           map g | g in FnSet(P) :: FE(D, g),
           Hooks(P, D),
           FnSet(P))
  }

  // ---------------- floors ----------------

  // fn(i): the function owning i.
  ghost function Owner(P: seq<OInstr>, i: nat): nat decreases i {
    if i in FnSet(P) || i == 0 then i else Owner(P, i - 1)
  }
  // f_F = 8 * floor(l_F / 8) (check.go:269; lookup.go:797-803).
  function Floor8(l: int): int { 8 * (l / 8) }
  ghost function Fl(P: seq<OInstr>, ell: nat -> int, i: nat): int { Floor8(ell(Owner(P, i))) }

  // ---------------- the windows and their specs ----------------

  // prologue-P9: no register changes, stores allowed (contract.go KindPass).
  function PassProSpec(f: int): Spec { Spec(f, {}, NoHelper, true, false, false, NoWrap, []) }
  // passload-P9: only r_G changes, no store (contract.go KindPassLoad).
  function PassLoadSpec(f: int, g: nat): Spec { Spec(f, {g}, NoHelper, false, false, false, NoWrap, []) }
  function SiteSpecFor(ins: OInstr, f: int, binds: seq<Bind>): Spec {
    if ins.Tail? then Api.TailSiteSpec(f) else Api.WithBinds(Api.SiteSpec(f), binds)
  }

  opaque ghost predicate Valid(raw: seq<bv8>, sp: Spec) { Checker.Validate(raw, sp) == Checker.Validated }

  // Every window of P' is validated by the region validator with the spec
  // of its kind (README.md, Dafny core; dafny/contract Spec).  S11: every
  // floor is the f_F of the function owning the window.
  ghost predicate AllValidated(P: seq<OInstr>, D: Decomp, ell: nat -> int) {
    (|D.pro0| > 0 ==> Valid(D.pro0, Api.EntryPrologueSpec(Fl(P, ell, 0))))
    && (forall g | g in D.fp ::
          if D.fp[g].kind == FP1b then Valid(D.fp[g].code, Api.CallbackPrologueSpec(Fl(P, ell, g)))
          else Valid(D.fp[g].code, PassProSpec(Fl(P, ell, g))))
    && (forall i | i in D.pl :: Valid(D.pl[i].code, PassLoadSpec(Fl(P, ell, i), D.pl[i].reg)))
    && (forall i | i in D.site && i !in D.wrap && i < |P| ::
          Valid(D.site[i].pre + Enc(P[i]) + D.site[i].post, SiteSpecFor(P[i], Fl(P, ell, i), D.site[i].binds)))
    && (forall i | i in D.wrap && i < |P| ::
          Valid(D.wrap[i].wp + EncCallLocal(WStart(P, D, i) - K(D, i) - 1),
                Api.WithBinds(Api.WrapSiteSpec(Fl(P, ell, i), D.wrap[i].body, Enc(P[i])), D.wrap[i].binds)))
    && (forall k | 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k].0.HookFn? ::
          Valid(AllFns(P, D)[k].0.body, Api.HookBodySpec()))
  }
}

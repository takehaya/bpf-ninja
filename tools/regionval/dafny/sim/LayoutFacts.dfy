// Where each piece of D sits in Layout(P, D).
include "Theorem.dfy"

module SimLayoutFacts {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import SimPremises

  lemma NsAt(b: seq<bv8>)
    ensures |Ns(b)| == NI(b)
    ensures forall k | 0 <= k < NI(b) :: Ns(b)[k] == N(Slice(b, k))
  {}

  // Wrapper bodies are present for every wrapper the layout places.
  ghost predicate FnsWF(P: seq<OInstr>, D: Decomp, gs: seq<InsFn>) {
    forall i | 0 <= i < |gs| :: gs[i].WrapFn? ==> gs[i].site in D.wrap && gs[i].site < |P|
  }

  lemma FnCodeLen(P: seq<OInstr>, D: Decomp, g: InsFn)
    requires g.WrapFn? ==> g.site in D.wrap && g.site < |P|
    ensures |FnCode(P, D, g)| == FnLen(D, g)
  {}

  lemma FnsCodeLen(P: seq<OInstr>, D: Decomp, gs: seq<InsFn>)
    requires FnsWF(P, D, gs)
    ensures |FnsCode(P, D, gs)| == FnsLen(D, gs)
    decreases |gs|
  {
    if |gs| > 0 {
      FnCodeLen(P, D, gs[0]);
      assert FnsWF(P, D, gs[1..]) by { forall i | 0 <= i < |gs[1..]| ensures gs[1..][i] == gs[i + 1] {} }
      FnsCodeLen(P, D, gs[1..]);
    }
  }

  ghost predicate AllFnsWF(P: seq<OInstr>, D: Decomp) {
    (forall i | i in D.fns :: FnsWF(P, D, D.fns[i])) && FnsWF(P, D, D.tail)
  }

  // The parts of Block(i), in order.
  lemma {:isolate_assertions} BlockParts(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D)
    ensures var fl := FnsLen(D, FnsAt(D, i));
      var fp := FPLen(D, i);
      var pl := PLLen(D, i);
      var pre := PreLen(D, i);
      var post := PostLen(D, i);
      var b := Block(P, D, i);
      |b| == BlockLen(D, i) && |FnsCode(P, D, FnsAt(D, i))| == fl
      && (forall k | 0 <= k < fl :: b[k] == FnsCode(P, D, FnsAt(D, i))[k])
      && (forall k | 0 <= k < fp :: b[fl + k] == N(Slice(D.fp[i].code, k)))
      && (forall k | 0 <= k < pl :: b[fl + fp + k] == N(Slice(D.pl[i].code, k)))
      && (forall k {:nowarn} | 0 <= k < pre :: b[fl + fp + pl + k] ==
            N(Slice(if i in D.wrap then D.wrap[i].wp else D.site[i].pre, k)))
      && b[fl + fp + pl + pre] == KappaTI(P, D, i)
      && (forall k | 0 <= k < post :: b[fl + fp + pl + pre + 1 + k] == N(Slice(D.site[i].post, k)))
  {
    reveal Block();
    assert FnsWF(P, D, FnsAt(D, i));
    FnsCodeLen(P, D, FnsAt(D, i));
    var p0 := FnsCode(P, D, FnsAt(D, i));
    var p1 := Ns(Opt(D.fp, i, (p: FProl) => p.code));
    var p2 := Ns(Opt(D.pl, i, (p: PassLoad) => p.code));
    var p3 := if i in D.wrap then Ns(D.wrap[i].wp) else Ns(Opt(D.site, i, (s: Site) => s.pre));
    var p5 := if i in D.wrap then [] else Ns(Opt(D.site, i, (s: Site) => s.post));
    assert Block(P, D, i) == p0 + p1 + p2 + p3 + [KappaTI(P, D, i)] + p5;
    assert |p1| == FPLen(D, i);
    assert |p2| == PLLen(D, i);
    assert |p3| == PreLen(D, i);
    assert |p5| == PostLen(D, i);
  }

  lemma BlockLenEq(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D)
    ensures |Block(P, D, i)| == BlockLen(D, i)
  {
    BlockParts(P, D, i);
  }

  lemma StartMono(D: Decomp, i: nat, j: nat)
    requires i <= j
    ensures Start(D, i) <= Start(D, j)
    decreases j - i
  {
    if i < j { StartMono(D, i, j - 1); }
  }

  lemma BlocksLen(P: seq<OInstr>, D: Decomp, i: nat)
    requires i <= |P| && AllFnsWF(P, D)
    ensures |Blocks(P, D, i)| == Start(D, |P|) - Start(D, i) && Start(D, i) <= Start(D, |P|)
    decreases |P| - i
  {
    if i < |P| { BlockLenEq(P, D, i); BlocksLen(P, D, i + 1); }
  }

  // Blocks(P, D, i) is Block(i) Block(i+1) ...
  lemma {:isolate_assertions} BlocksAt(P: seq<OInstr>, D: Decomp, i: nat, j: nat, k: nat)
    requires i <= j < |P| && k < BlockLen(D, j) && AllFnsWF(P, D)
    ensures |Blocks(P, D, i)| == Start(D, |P|) - Start(D, i)
    ensures Start(D, i) <= Start(D, j) && Start(D, j) + BlockLen(D, j) <= Start(D, |P|)
    ensures |Block(P, D, j)| == BlockLen(D, j)
    ensures Blocks(P, D, i)[Start(D, j) - Start(D, i) + k] == Block(P, D, j)[k]
    decreases |P| - i
  {
    BlockLenEq(P, D, j);
    BlockLenEq(P, D, i);
    BlocksLen(P, D, i);
    BlocksLen(P, D, i + 1);
    StartMono(D, i, j); StartMono(D, j + 1, |P|);
    var bi := Block(P, D, i);
    var rest := Blocks(P, D, i + 1);
    assert Blocks(P, D, i) == bi + rest;
    assert Start(D, i + 1) == Start(D, i) + BlockLen(D, i);
    if i < j {
      BlocksAt(P, D, i + 1, j, k);
      assert (bi + rest)[|bi| + (Start(D, j) - Start(D, i + 1) + k)] == rest[Start(D, j) - Start(D, i + 1) + k];
    } else {
      assert (bi + rest)[k] == bi[k];
    }
  }

  // ---------------- the code of P' ----------------

  lemma LayoutIs(P: seq<OInstr>, D: Decomp)
    ensures Layout(P, D).code == Ns(D.pro0) + Blocks(P, D, 0) + FnsCode(P, D, D.tail)
    ensures Layout(P, D).fentry == map g | g in FnSet(P) :: FE(D, g)
    ensures Layout(P, D).hooks == Hooks(P, D) && Layout(P, D).fns == FnSet(P)
  { reveal Layout(); }

  lemma CodeLen(P: seq<OInstr>, D: Decomp)
    requires AllFnsWF(P, D)
    ensures |Layout(P, D).code| == Start(D, |P|) + FnsLen(D, D.tail)
  {
    LayoutIs(P, D);
    BlocksLen(P, D, 0);
    NsAt(D.pro0);
    assert FnsWF(P, D, D.tail);
    FnsCodeLen(P, D, D.tail);
  }

  // The layout's code: the entry prologue, then the blocks, then the trailing functions.
  lemma {:isolate_assertions} CodeAt(P: seq<OInstr>, D: Decomp, j: nat, k: nat)
    requires j < |P| && k < BlockLen(D, j) && AllFnsWF(P, D)
    ensures Start(D, j) + k < |Layout(P, D).code|
    ensures |Block(P, D, j)| == BlockLen(D, j)
    ensures Layout(P, D).code[Start(D, j) + k] == Block(P, D, j)[k]
  {
    BlocksAt(P, D, 0, j, k);
    CodeLen(P, D);
    LayoutIs(P, D);
    NsAt(D.pro0);
    var a := Ns(D.pro0);
    var b := Blocks(P, D, 0);
    var t := FnsCode(P, D, D.tail);
    assert Start(D, 0) == |a|;
    assert (a + b + t)[|a| + (Start(D, j) - Start(D, 0) + k)] == b[Start(D, j) - Start(D, 0) + k];
  }

  lemma {:isolate_assertions} CodePro(P: seq<OInstr>, D: Decomp, k: nat)
    requires k < NI(D.pro0) && AllFnsWF(P, D)
    ensures k < |Layout(P, D).code| && Layout(P, D).code[k] == N(Slice(D.pro0, k))
  {
    CodeLen(P, D);
    LayoutIs(P, D);
    NsAt(D.pro0);
    var a := Ns(D.pro0);
    var b := Blocks(P, D, 0);
    var t := FnsCode(P, D, D.tail);
    assert (a + b + t)[k] == a[k];
  }

  lemma {:isolate_assertions} CodeTail(P: seq<OInstr>, D: Decomp, k: nat)
    requires k < FnsLen(D, D.tail) && AllFnsWF(P, D)
    ensures Start(D, |P|) + k < |Layout(P, D).code|
    ensures |FnsCode(P, D, D.tail)| == FnsLen(D, D.tail)
    ensures Layout(P, D).code[Start(D, |P|) + k] == FnsCode(P, D, D.tail)[k]
  {
    assert FnsWF(P, D, D.tail);
    CodeLen(P, D);
    LayoutIs(P, D);
    BlocksLen(P, D, 0);
    NsAt(D.pro0);
    FnsCodeLen(P, D, D.tail);
    var a := Ns(D.pro0);
    var b := Blocks(P, D, 0);
    var t := FnsCode(P, D, D.tail);
    assert Start(D, 0) == |a|;
    assert |a + b| == Start(D, |P|);
    assert (a + b + t)[|a + b| + k] == t[k];
  }

  // ---------------- inserted functions ----------------

  lemma FnStartsLen(D: Decomp, gs: seq<InsFn>, base: nat)
    ensures |FnStarts(D, gs, base)| == |gs|
    decreases |gs|
  {
    if |gs| > 0 { FnStartsLen(D, gs[1..], base + FnLen(D, gs[0])); }
  }

  lemma FnStartsAt(D: Decomp, gs: seq<InsFn>, base: nat, q: nat)
    requires q < |gs|
    ensures |FnStarts(D, gs, base)| == |gs|
    ensures FnStarts(D, gs, base)[q] == (gs[q], base + FnsLen(D, gs[..q]))
    decreases |gs|
  {
    FnStartsLen(D, gs, base);
    if q > 0 {
      FnStartsAt(D, gs[1..], base + FnLen(D, gs[0]), q - 1);
      assert gs[1..][..q - 1] == gs[..q][1..];
      assert FnsLen(D, gs[..q]) == FnLen(D, gs[..q][0]) + FnsLen(D, gs[..q][1..]);
    } else {
      assert FnsLen(D, gs[..0]) == 0;
    }
  }

  lemma FnsLenPrefix(D: Decomp, gs: seq<InsFn>, q: nat)
    requires q <= |gs|
    ensures FnsLen(D, gs[..q]) <= FnsLen(D, gs)
    decreases |gs|
  {
    if q > 0 {
      FnsLenPrefix(D, gs[1..], q - 1);
      assert gs[1..][..q - 1] == gs[..q][1..];
      assert FnsLen(D, gs[..q]) == FnLen(D, gs[..q][0]) + FnsLen(D, gs[..q][1..]);
    } else {
      assert FnsLen(D, gs[..0]) == 0;
    }
  }

  // FnsCode(gs) is FnCode(gs[0]) FnCode(gs[1]) ...
  lemma {:isolate_assertions} FnsCodeAt(P: seq<OInstr>, D: Decomp, gs: seq<InsFn>, q: nat, r: nat)
    requires FnsWF(P, D, gs) && q < |gs| && r < FnLen(D, gs[q])
    ensures FnsLen(D, gs[..q]) + r < FnsLen(D, gs) && |FnsCode(P, D, gs)| == FnsLen(D, gs)
    ensures |FnCode(P, D, gs[q])| == FnLen(D, gs[q])
    ensures FnsCode(P, D, gs)[FnsLen(D, gs[..q]) + r] == FnCode(P, D, gs[q])[r]
    decreases |gs|
  {
    FnsCodeLen(P, D, gs);
    FnCodeLen(P, D, gs[0]);
    FnCodeLen(P, D, gs[q]);
    assert FnsWF(P, D, gs[1..]) by { forall i | 0 <= i < |gs[1..]| ensures gs[1..][i] == gs[i + 1] {} }
    FnsCodeLen(P, D, gs[1..]);
    var a := FnCode(P, D, gs[0]);
    var b := FnsCode(P, D, gs[1..]);
    assert FnsCode(P, D, gs) == a + b;
    if q > 0 {
      FnsCodeAt(P, D, gs[1..], q - 1, r);
      assert gs[1..][..q - 1] == gs[..q][1..];
      assert gs[1..][q - 1] == gs[q];
      assert FnsLen(D, gs[..q]) == FnLen(D, gs[..q][0]) + FnsLen(D, gs[..q][1..]);
      assert (a + b)[|a| + (FnsLen(D, gs[1..][..q - 1]) + r)] == b[FnsLen(D, gs[1..][..q - 1]) + r];
    } else {
      assert FnsLen(D, gs[..0]) == 0;
      assert (a + b)[r] == a[r];
    }
  }

  // An inserted function's code sits at its entry.
  ghost predicate PlacedIn(P: seq<OInstr>, D: Decomp, gt: (InsFn, nat)) {
    var (g, t) := gt;
    t + FnLen(D, g) <= |Layout(P, D).code| && |FnCode(P, D, g)| == FnLen(D, g)
    && forall r | 0 <= r < FnLen(D, g) :: Layout(P, D).code[t + r] == FnCode(P, D, g)[r]
  }

  lemma {:isolate_assertions} PlacedBlock(P: seq<OInstr>, D: Decomp, i: nat, q: nat)
    requires i < |P| && AllFnsWF(P, D) && q < |FnsAt(D, i)|
    ensures |FnStarts(D, FnsAt(D, i), Start(D, i))| == |FnsAt(D, i)| && PlacedIn(P, D, FnStarts(D, FnsAt(D, i), Start(D, i))[q])
  {
    var gs := FnsAt(D, i);
    assert FnsWF(P, D, gs);
    FnStartsAt(D, gs, Start(D, i), q);
    BlockParts(P, D, i);
    FnCodeLen(P, D, gs[q]);
    FnsCodeLen(P, D, gs);
    var t := Start(D, i) + FnsLen(D, gs[..q]);
    var code := Layout(P, D).code;
    forall r | 0 <= r < FnLen(D, gs[q]) ensures t + r < |code| && code[t + r] == FnCode(P, D, gs[q])[r]
    {
      FnsCodeAt(P, D, gs, q, r);
      CodeAt(P, D, i, FnsLen(D, gs[..q]) + r);
    }
    FnsLenPrefix(D, gs[..q + 1], q);
    FnsLenPrefix(D, gs, q + 1);
    assert gs[..q + 1][..q] == gs[..q];
    CodeLen(P, D);
    BlocksAt(P, D, 0, i, 0);
    FnsLenSnoc(D, gs, q);
  }

  lemma FnsLenSnoc(D: Decomp, gs: seq<InsFn>, q: nat)
    requires q < |gs|
    ensures FnsLen(D, gs[..q]) + FnLen(D, gs[q]) <= FnsLen(D, gs)
    decreases |gs|
  {
    if q > 0 {
      FnsLenSnoc(D, gs[1..], q - 1);
      assert gs[1..][..q - 1] == gs[..q][1..];
      assert FnsLen(D, gs[..q]) == FnLen(D, gs[..q][0]) + FnsLen(D, gs[..q][1..]);
    } else {
      assert FnsLen(D, gs[..0]) == 0;
    }
  }

  lemma {:isolate_assertions} PlacedTail(P: seq<OInstr>, D: Decomp, q: nat)
    requires AllFnsWF(P, D) && q < |D.tail|
    ensures |FnStarts(D, D.tail, Start(D, |P|))| == |D.tail| && PlacedIn(P, D, FnStarts(D, D.tail, Start(D, |P|))[q])
  {
    var gs := D.tail;
    assert FnsWF(P, D, gs);
    FnStartsAt(D, gs, Start(D, |P|), q);
    FnCodeLen(P, D, gs[q]);
    CodeLen(P, D);
    FnsCodeLen(P, D, gs);
    FnsLenSnoc(D, gs, q);
    var t := Start(D, |P|) + FnsLen(D, gs[..q]);
    var code := Layout(P, D).code;
    forall r | 0 <= r < FnLen(D, gs[q]) ensures t + r < |code| && code[t + r] == FnCode(P, D, gs[q])[r]
    {
      FnsCodeAt(P, D, gs, q, r);
      CodeTail(P, D, FnsLen(D, gs[..q]) + r);
    }
  }

  lemma AllFnsFromPlaced(P: seq<OInstr>, D: Decomp, i: nat, k: nat)
    requires i <= |P| && AllFnsWF(P, D) && k < |AllFnsFrom(D, |P|, i)|
    ensures PlacedIn(P, D, AllFnsFrom(D, |P|, i)[k])
    decreases |P| - i
  {
    if i >= |P| {
      FnStartsLen(D, D.tail, Start(D, |P|));
      PlacedTail(P, D, k);
    } else {
      var a := FnStarts(D, FnsAt(D, i), Start(D, i));
      FnStartsLen(D, FnsAt(D, i), Start(D, i));
      var b := AllFnsFrom(D, |P|, i + 1);
      assert AllFnsFrom(D, |P|, i) == a + b;
      if k < |a| { PlacedBlock(P, D, i, k); assert (a + b)[k] == a[k]; }
      else { AllFnsFromPlaced(P, D, i + 1, k - |a|); assert (a + b)[k] == b[k - |a|]; }
    }
  }

  lemma AllFnsPlaced(P: seq<OInstr>, D: Decomp, k: nat)
    requires AllFnsWF(P, D) && k < |AllFns(P, D)|
    ensures PlacedIn(P, D, AllFns(P, D)[k])
  { AllFnsFromPlaced(P, D, 0, k); }

  // ---------------- entry points ----------------

  // An instruction that is not exit or ja is followed, in P', by the entry of the next one.
  lemma {:isolate_assertions} NextE(P: seq<OInstr>, D: Decomp, j: nat)
    requires SimPremises.PiecesOk(P, D) && SimPremises.E0Shape(P)
    requires j < |P| && !P[j].Exit? && !P[j].Ja?
    ensures j + 1 < |P| && E(D, j + 1) == K(D, j) + 1 + PostLen(D, j)
  {
    assert j + 1 != |P|;
    assert j + 1 !in FnSet(P);
    assert j + 1 !in D.fns;
    assert j + 1 !in D.fp;
    assert FnsAt(D, j + 1) == [];
    assert FnsLen(D, []) == 0;
    assert Start(D, j + 1) == Start(D, j) + BlockLen(D, j);
  }

  // Without a pass load or a prelude, the entry of j is j's own instruction.
  lemma EK(D: Decomp, j: nat)
    requires j !in D.pl && j !in D.site && j !in D.wrap
    ensures K(D, j) == E(D, j) && PostLen(D, j) == 0
  {}

  lemma {:isolate_assertions} E0Pro(P: seq<OInstr>, D: Decomp)
    requires SimPremises.PiecesOk(P, D)
    ensures E(D, 0) == NI(D.pro0)
  {
    assert 0 !in D.fns;
    assert 0 !in D.fp;
    assert FnsAt(D, 0) == [];
    assert FnsLen(D, []) == 0;
  }

  // The pieces of a site window in P'.
  lemma {:isolate_assertions} SiteCode(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D) && i in D.site && i !in D.wrap && i !in D.pl
    ensures K(D, i) == E(D, i) + NI(D.site[i].pre) && PostLen(D, i) == NI(D.site[i].post)
    ensures K(D, i) + NI(D.site[i].post) < |Layout(P, D).code|
    ensures forall r | 0 <= r < NI(D.site[i].pre) ::
      E(D, i) + r < |Layout(P, D).code| && Layout(P, D).code[E(D, i) + r] == N(Slice(D.site[i].pre, r))
    ensures Layout(P, D).code[K(D, i)] == O(Reloc(D, P[i]), i)
    ensures forall r | 0 <= r < NI(D.site[i].post) ::
      K(D, i) + 1 + r < |Layout(P, D).code| && Layout(P, D).code[K(D, i) + 1 + r] == N(Slice(D.site[i].post, r))
  {
    BlockParts(P, D, i);
    var fl := FnsLen(D, FnsAt(D, i));
    var fp := FPLen(D, i);
    var code := Layout(P, D).code;
    assert PLLen(D, i) == 0;
    assert E(D, i) == Start(D, i) + fl + fp;
    forall r | 0 <= r < NI(D.site[i].pre)
      ensures E(D, i) + r < |code| && code[E(D, i) + r] == N(Slice(D.site[i].pre, r))
    {
      CodeAt(P, D, i, fl + fp + r);
    }
    CodeAt(P, D, i, fl + fp + NI(D.site[i].pre));
    forall r | 0 <= r < NI(D.site[i].post)
      ensures K(D, i) + 1 + r < |code| && code[K(D, i) + 1 + r] == N(Slice(D.site[i].post, r))
    {
      CodeAt(P, D, i, fl + fp + NI(D.site[i].pre) + 1 + r);
    }
    CodeAt(P, D, i, fl + fp + NI(D.site[i].pre) + NI(D.site[i].post));
  }

  // The instruction at the entry of an instruction with no inserted code.
  lemma {:isolate_assertions} PlainCode(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D) && i !in D.site && i !in D.wrap && i !in D.pl
    ensures K(D, i) == E(D, i) && K(D, i) < |Layout(P, D).code|
    ensures Layout(P, D).code[K(D, i)] == O(Reloc(D, P[i]), i)
  {
    BlockParts(P, D, i);
    CodeAt(P, D, i, FnsLen(D, FnsAt(D, i)) + FPLen(D, i));
  }
}

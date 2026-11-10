// Basic facts about the whole-program model, used by the simulation proof.
include "Theorem.dfy"

module SimFacts {
  import opened Bits
  import opened SimModel
  import Obligations
  import Semantics

  // Registers that are all readable are read as their words.
  ghost function Words(f: Frame, rs: seq<nat>): seq<bv64> {
    seq(|rs|, i requires 0 <= i < |rs| => if Reg(f, rs[i]).W? then Reg(f, rs[i]).w else 0)
  }

  lemma RdsAll(f: Frame, rs: seq<nat>)
    requires forall i | 0 <= i < |rs| :: Reg(f, rs[i]).W?
    ensures Rds(f, rs) == Some(Words(f, rs))
    decreases |rs|
  {
    if |rs| > 0 {
      RdsAll(f, rs[1..]);
      assert Reg(f, rs[0]) == W(Reg(f, rs[0]).w);
      assert Rds(f, rs) == Some([Reg(f, rs[0]).w] + Words(f, rs[1..]));
      assert [Reg(f, rs[0]).w] + Words(f, rs[1..]) == Words(f, rs);
    } else {
      assert Words(f, rs) == [];
    }
  }

  // Reading an unreadable register gives None.
  lemma RdsBot(f: Frame, rs: seq<nat>, i: nat)
    requires i < |rs| && Reg(f, rs[i]).Bot?
    ensures Rds(f, rs) == None
    decreases |rs|
  {
    if i > 0 { RdsBot(f, rs[1..], i - 1); }
  }

  // An empty write set changes nothing.
  lemma ApplyNone(c: Cfg) ensures ApplyW(c, map[]) == c
  {
    reveal ApplyW();
    var c' := ApplyW(c, map[]);
    forall d | 0 <= d < |c.fr| ensures c'.fr[d] == c.fr[d] {
      assert c'.fr[d].stack == c.fr[d].stack;
    }
    assert c'.fr == c.fr;
    assert c'.L.mem == c.L.mem;
  }

  lemma CountHelpersMono(a: seq<Semantics.Event>, b: seq<Semantics.Event>)
    requires a <= b
    ensures Obligations.CountHelpers(a) <= Obligations.CountHelpers(b)
    decreases |b|
  {
    if |a| < |b| {
      assert a <= b[..|b| - 1];
      CountHelpersMono(a, b[..|b| - 1]);
    }
  }
}

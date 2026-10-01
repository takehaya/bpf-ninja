import Kunai.Eval.Core

/-!
# p4lite parser machine semantics (§14, small-step)

`ψ = ⟨s, π, α⟩` is `MState`: the current state index, the cursor (absolute
byte offset into the packet), the counters, and `α` as the list of extracted
aux views. One `step` executes a state's statements and its transition.
`run` iterates with two bounds: `MAX_DEPTH` counts loop iterations
(transitions to the same or an earlier state; exhausting it accepts, as the
implementation's `bpf_loop` cap does, D-026), and a structural fuel that only
guarantees termination.
-/
namespace Kunai

structure MState where
  state : Nat
  cursor : Nat
  counters : List (String × Nat) := []
  views : List AuxView := []
  patches : List (Nat × Nat) := []
  deriving Repr, BEq, DecidableEq

/-- Reasons a machine run stops without accepting. -/
inductive MFail
  | reject
  | illTyped (reason : String)
  deriving Repr, BEq, DecidableEq

private def MState.counter (ψ : MState) (c : String) : Nat :=
  (ψ.counters.find? (·.1 == c)).map (·.2) |>.getD 0

private def MState.setCounter (ψ : MState) (c : String) (v : Nat) : MState :=
  { ψ with counters := (c, v) :: ψ.counters.filter (·.1 != c) }

/-- The most recent view of an out parameter (option or stack). -/
def latestView (views : List AuxView) (outParam : String) : Option AuxView :=
  (views.reverse.find? (·.outParam == outParam))

def stackViews (views : List AuxView) (stack : String) : List AuxView :=
  views.filter fun v => v.outParam == stack && v.stackIdx.isSome

private def byteAt (P : Packet) (off : Nat) : Except MFail Nat :=
  match readBytes P off 1 with
  | some b => pure b
  | none => throw .reject

private def viewByte (P : Packet) (views : List AuxView) (target : String) (byteOff : Nat) : Except MFail Nat :=
  match latestView views target with
  | some v => byteAt P (v.off + byteOff)
  | none => throw (.illTyped s!"parser reads {target} before extracting it")

/-- P-Extract / P-Extract-Stack / P-Extract-Stack-Full, plus the variable
tail and write-back annotations of the extracted header. -/
private def doExtract (P : Packet) (m : Machine) (layerOff : Nat) (ψ : MState) (e : Extract) : Except MFail MState := do
  let stackIdx ← if e.stackPush then
      let some sd := m.stack? e.outParam | throw (.illTyped s!"unknown stack {e.outParam}")
      let k := (stackViews ψ.views e.outParam).length
      if k ≥ sd.capacity then throw .reject
      pure (some k)
    else pure none
  if ψ.cursor + e.bytes > P.length then throw .reject
  let mut view : AuxView := { outParam := e.outParam, header := e.header, stackIdx, off := ψ.cursor, len := e.bytes }
  let mut cursor := ψ.cursor + e.bytes
  if let some (_, t) := m.tails.find? (·.1 == e.header) then
    let b ← byteAt P (view.off + t.byteOff)
    let some extra := t.apply b | throw .reject
    if cursor + extra > P.length then throw .reject
    view := { view with len := view.len + extra }
    cursor := cursor + extra
  let mut patches := ψ.patches
  if let some (_, wb) := m.writebacks.find? (·.1 == e.header) then
    let v ← byteAt P (view.off + wb.sourceByteOff)
    patches := patches ++ [(layerOff + wb.parentByteOff, v)]   -- in order: the last extension wins
  pure { ψ with cursor, views := ψ.views ++ [view], patches }

private def doCounter (P : Packet) (layerOff : Nat) (ψ : MState) : CounterOp → Except MFail MState
  | .set c len => do
    let b ← byteAt P (layerOff + len.byteOff)
    match len.apply b with
    | some v => pure (ψ.setCounter c v)
    | none => throw .reject
  | .decLiteral c n => dec c n
  | .decField c target byteOff => do dec c (← viewByte P ψ.views target byteOff)
  | .decLookahead c byteOff => do dec c (← byteAt P (ψ.cursor + byteOff))
where
  dec (c : String) (n : Nat) : Except MFail MState :=
    let cur := ψ.counter c
    if n > cur then throw .reject else pure (ψ.setCounter c (cur - n))

private def doAdvance (P : Packet) (ψ : MState) : AdvanceOp → Except MFail MState
  | .literal n => adv n
  | .field target len => do
    let b ← viewByte P ψ.views target len.byteOff
    match len.apply b with
    | some n => adv n
    | none => throw .reject
  | .lookahead len => do
    let b ← byteAt P (ψ.cursor + len.byteOff)
    match len.apply b with
    -- D-028: a length-driven advance must move past the bytes it read,
    -- else the walk makes no progress (TLV length 0 or 1).
    | some n => if n ≤ len.byteOff then throw .reject else adv n
    | none => throw .reject
where
  adv (n : Nat) : Except MFail MState :=
    if ψ.cursor + n > P.length then throw .reject else pure { ψ with cursor := ψ.cursor + n }

inductive KeyVal
  | nat (n : Nat)
  | bool (b : Bool)
  deriving Repr, BEq, DecidableEq

/-- `eval-key` (§14.3). A lookahead past the end of the packet is
unreadable (`none`): it matches only wildcards, so `(true, _)` still ends a
walk whose counter is exhausted exactly at the packet end (D-033). -/
private def evalKey (P : Packet) (ψ : MState) : SelectKey → Except MFail (Option KeyVal)
  | .field target stackLast bitOff width => do
    let view? := if stackLast then (stackViews ψ.views target).getLast? else latestView ψ.views target
    let some v := view? | throw (.illTyped s!"select reads {target} before extracting it")
    match readBits P (v.off * 8 + bitOff) width with
    | some n => pure (some (.nat n))
    | none => throw .reject
  | .lookahead bits => pure ((readBits P (ψ.cursor * 8) bits).map .nat)
  | .counterIsZero c => pure (some (.bool (ψ.counter c == 0)))

private def valMatches : MatchVal → Option KeyVal → Bool
  | .wild, _ => true
  | .val n, some (.nat k) => n == k
  | .bool b, some (.bool k) => b == k
  | _, _ => false

/-- TLV option sighting (D-030): when the walk dispatches on a lookahead
kind byte — the matched case names that kind (`(false, 5): parse_sack`) —
the option's view starts at the cursor, whether or not the target state
extracts it (`sack`, `rr` advance by length instead). A lookahead taken
after the counter ran out (`(true, _)`) sights nothing. The latest sighting
wins. -/
private def sightOptions (m : Machine) (ψ : MState) (hit : SelectCase) (keys : List SelectKey) : MState :=
  let extractsIt (o : OptionDecl) : Bool :=
    match hit.target with
    | .state i => (m.states[i]?.map fun s => s.extracts.any (·.outParam == o.outParam)).getD false
    | _ => false
  (keys.zip hit.values).foldl (fun ψ (k, v) =>
    match k, v with
    | .lookahead _, .val n =>
      -- an option whose target state extracts it gets its view from the extract
      match m.options.find? fun o => o.kindByte == some n && !extractsIt o with
      | some o =>
        let bytes := ((m.header? o.header).map (·.bytes)).getD 0
        { ψ with views := ψ.views ++ [{ outParam := o.outParam, header := o.header, off := ψ.cursor, len := bytes }] }
      | none => ψ
    | _, _ => ψ) ψ

/-- P-Trans-Select: the first case whose values all match wins. -/
private def selectTarget (P : Packet) (m : Machine) (ψ : MState) (s : Select) : Except MFail (MState × Target) := do
  let keys ← s.keys.mapM (evalKey P ψ)
  match s.cases.find? fun c => c.values.length == keys.length && (c.values.zip keys).all fun (v, k) => valMatches v k with
  | some c => pure (sightOptions m ψ c s.keys, c.target)
  | none => pure (ψ, s.default)

/-- One state: statements in the loader's order (extracts, counters,
advances), then the transition. -/
def step (P : Packet) (m : Machine) (layerOff : Nat) (ψ : MState) (s : ParseState) : Except MFail (MState × Target) := do
  let mut ψ := ψ
  for e in s.extracts do ψ ← doExtract P m layerOff ψ e
  for c in s.counters do ψ ← doCounter P layerOff ψ c
  for a in s.advances do ψ ← doAdvance P ψ a
  match s.trans with
  | .goto t => pure (ψ, t)
  | .select sel => selectTarget P m ψ sel

/-- Runs the machine from `layerOff`. `depth` is `MAX_DEPTH`: each transition
to the same or an earlier state consumes one, and exhausting it accepts
(D-026). `fuel` is a structural bound on state entries. -/
def run (P : Packet) (m : Machine) (layerOff : Nat) : Nat → Nat → MState → Except MFail MState
  | 0, _, _ => throw (.illTyped "parser machine exceeded its step budget")
  | fuel + 1, depth, ψ => do
    let some s := m.states[ψ.state]? | throw (.illTyped s!"parser state {ψ.state} does not exist")
    let (ψ', t) ← step P m layerOff ψ s
    match t with
    | .accept => pure ψ'
    | .reject => throw .reject
    | .state i =>
      if i ≤ ψ.state then
        match depth with
        | 0 => pure ψ'
        | d + 1 => run P m layerOff fuel d { ψ' with state := i }
      else run P m layerOff fuel depth { ψ' with state := i }

/-- `aux-extract(p, π, P, α)` (§14.4) for a layer starting at `layerOff`. -/
def runMachine (P : Packet) (spec : ProtoSpec) (m : Machine) (layerOff : Nat) : Except MFail MState :=
  run P m layerOff (m.states.length * (spec.maxDepth + 2) + 1) spec.maxDepth { state := m.entry, cursor := layerOff }

end Kunai

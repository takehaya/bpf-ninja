import Kunai

open Lean (Json)

/-- `lake exe gen`: print every vector as a JSON array, one vector per line,
sorted by `id`, so the output is stable and diffs stay readable. -/
def main : IO Unit := do
  let vs := Kunai.vectors.toArray.qsort (·.id < ·.id)
  IO.println "["
  for h : i in [0:vs.size] do
    let sep := if i + 1 < vs.size then "," else ""
    IO.println s!"  {(vs[i]'h.upper).toJson.compress}{sep}"
  IO.println "]"

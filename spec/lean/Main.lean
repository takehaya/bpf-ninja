import Kunai

/-- `lake exe gen`: print every vector as a JSON array, one vector per line,
sorted by `id`, so the output is stable and diffs stay readable. -/
def main : IO Unit := do
  let vs := Kunai.vectors.toArray.qsort (·.id < ·.id)
  IO.println "["
  IO.println (String.intercalate ",\n" (vs.toList.map fun v => "  " ++ v.toJson.compress))
  IO.println "]"

import Kunai
import Kunai.Gen

/-- `lake exe gen [--generated]`: print the golden vectors (or, with
`--generated`, the mutated ones) as a JSON array, one vector per line,
sorted by `id`, so the output is stable and diffs stay readable. -/
def main (args : List String) : IO Unit := do
  let src := if args.contains "--generated" then Kunai.generatedVectors else Kunai.vectors
  let vs := src.toArray.qsort (·.id < ·.id)
  IO.println "["
  IO.println (String.intercalate ",\n" (vs.toList.map fun v => "  " ++ v.toJson.compress))
  IO.println "]"

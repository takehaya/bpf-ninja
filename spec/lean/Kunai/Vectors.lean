import Kunai.Vectors.Base
import Kunai.Vectors.Syntax
import Kunai.Vectors.Chain
import Kunai.Vectors.Where
import Kunai.Vectors.AuxHeaders

/-!
# Golden vectors

`vectors` is what `lake exe gen` exports to
`pkg/kunai/dsltest/testdata/spec_vectors.json`. Each vector is defined with
the `vector` macro, which also proves `eval … = expected` by `decide`.
-/
namespace Kunai

def vectors : List Vector := syntaxVectors ++ chainVectors ++ whereVectors ++ auxVectors

/-- Ids are unique; the Go test names subtests after them. `native_decide`
because `decide` exceeds the recursion limit on `eraseDups` over 100+ strings. -/
example : (vectors.map (·.id)).eraseDups.length = vectors.length := by native_decide

end Kunai

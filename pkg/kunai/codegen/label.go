package codegen

import "fmt"

// labeler numbers the `dsl_<prefix>_<n>` labels of one compile. Gen
// creates one and reaches every emitter through queriedOptions.labels and
// predCtx.labels, so the numbers depend only on the filter: labels need
// to be unique within one instruction stream (Main and Callbacks), never
// across compiles.
type labeler struct {
	next map[string]int
}

func newLabeler() *labeler { return &labeler{next: map[string]int{}} }

// fresh returns `dsl_<prefix>_<n>`, n counting from 1 per prefix.
func (l *labeler) fresh(prefix string) string {
	if l == nil {
		panic("codegen: label minted without a labeler; queriedOptions and predCtx must come from Gen")
	}
	l.next[prefix]++
	return fmt.Sprintf("dsl_%s_%d", prefix, l.next[prefix])
}

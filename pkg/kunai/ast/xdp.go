package ast

// XDPActions is the set of XDP return action identifiers recognised
// by the DSL. They appear in where-clause "action == <name>" atoms and
// are simultaneously reserved as @label names so a label never shadows
// an action constant.
var XDPActions = map[string]bool{
	"XDP_PASS":     true,
	"XDP_DROP":     true,
	"XDP_TX":       true,
	"XDP_ABORTED":  true,
	"XDP_REDIRECT": true,
}

// IsXDPAction reports whether name is a recognised XDP action.
func IsXDPAction(name string) bool { return XDPActions[name] }

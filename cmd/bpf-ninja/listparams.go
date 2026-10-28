package main

import (
	"fmt"
	"io"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/urfave/cli/v3"
)

func validateMembersFlags(cmd *cli.Command) error {
	if cmd.Bool("members") {
		if !cmd.Bool("list-params") {
			return fmt.Errorf("--members requires --list-params")
		}
		if cmd.Bool("list-progs") || cmd.Bool("list-funcs") || cmd.String("dump-asm") != "" {
			return fmt.Errorf("--members cannot be combined with --list-progs, --list-funcs, or --dump-asm")
		}
	} else if cmd.IsSet("members-depth") {
		return fmt.Errorf("--members-depth requires --list-params --members")
	}
	if depth := cmd.Int("members-depth"); depth < 1 || depth > attach.MaxMembersDepth {
		return fmt.Errorf("--members-depth must be between 1 and %d", attach.MaxMembersDepth)
	}
	return nil
}

func paramsToJSON(t attach.Target, members bool, depth int) paramsTargetJSON {
	out := paramsTargetJSON{Func: t.FuncName, ID: t.ProgID, Params: []paramJSON{}}
	for _, p := range t.Params {
		n := paramJSON{Name: p.Name, Index: p.Index, Size: p.Size, Signed: p.Signed, Kind: p.Kind, TypeName: p.TypeName}
		if members && p.Kind != "" {
			n.Type = attach.ArgTypeName(p.Type)
			children, truncated := attach.ListArgMembers(p, depth)
			n.Members, n.MembersTruncated = &children, truncated
		}
		out.Params = append(out.Params, n)
	}
	return out
}

func printParams(w io.Writer, t paramsTargetJSON) {
	_, _ = fmt.Fprintf(w, "Filterable parameters for %s (id=%d):\n", t.Func, t.ID)
	if len(t.Params) == 0 {
		_, _ = fmt.Fprintln(w, "  (none - integer or pointer parameters after the first argument are supported)")
	}
	for _, p := range t.Params {
		if p.Members != nil {
			_, _ = fmt.Fprintf(w, "  %s: %s (arg index %d)\n", p.Name, p.Type, p.Index)
			printMembers(w, *p.Members, p.MembersTruncated, "    ")
		} else if p.Kind != "" {
			hint := p.Name + "->member"
			if p.Kind == "ptr" {
				hint = p.Name + "[0] for scalar pointers"
			}
			_, _ = fmt.Fprintf(w, "  %-20s [%s %s, arg index %d; use %s or %s==null]\n", p.Name, p.Kind, p.TypeName, p.Index, hint, p.Name)
		} else {
			_, _ = fmt.Fprintf(w, "  %-20s [%d bytes, %s, arg index %d]\n", p.Name, p.Size, signedness(p.Signed), p.Index)
		}
	}
}

func printMembers(w io.Writer, members []attach.ArgMemberInfo, truncated, indent string) {
	for _, m := range members {
		typ := m.Type
		if m.Bitfield != 0 {
			typ += fmt.Sprintf(":%d", m.Bitfield)
		}
		detail := fmt.Sprintf("off %d", m.Offset)
		if m.BitOffset != 0 {
			detail += fmt.Sprintf(" + %d bits", m.BitOffset)
		}
		if m.Size != nil {
			detail += fmt.Sprintf("  size %d", *m.Size)
		} else {
			detail += "  size unknown"
		}
		if m.Signed != nil {
			detail += "  " + signedness(*m.Signed)
		}
		status := "filterable"
		if !m.Filterable {
			status = "(not filterable: " + m.Reason + ")"
		}
		_, _ = fmt.Fprintf(w, "%s%s  %s  %s  %s\n", indent, m.Expression, typ, detail, status)
		printMembers(w, m.Members, m.Truncated, indent+"  ")
	}
	if truncated != "" {
		_, _ = fmt.Fprintf(w, "%s... (%s; members omitted)\n", indent, truncated)
	}
}

func signedness(signed bool) string {
	if signed {
		return "signed"
	}
	return "unsigned"
}

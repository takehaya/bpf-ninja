// Package recordbuild turns a capture target and its filters into the fixed
// record.Layout the BPF side writes. It is kept apart from the leaf package
// internal/record (the on-wire block and its decoder) because it depends on
// internal/attach and internal/filter.
package recordbuild

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/record"
)

// Options select the layout for one capture.
type Options struct {
	Mode record.Mode
	// Explicit records at every target; otherwise only at generated hooks
	// (see Generated). It also decides whether an over-limit layout errors
	// or quietly turns off.
	Explicit bool
	MaxBytes int
}

// Generated reports whether the target is a hook inject-run generated: its
// BTF function carries the hook decl tag. Parameter names alone are not
// enough, since an ordinary function may use the same names.
func Generated(t attach.Target) bool { return t.Generated }

// Build returns the layout of one target, or nil when nothing applies. A
// default capture (not Explicit) that would exceed a limit turns itself off
// and returns nil; an explicit one returns the error.
func Build(t attach.Target, tf filter.TargetFilters, opt Options) (*record.Layout, error) {
	if opt.Mode == record.ModeNone || opt.Mode == "" {
		return nil, nil
	}
	if !opt.Explicit && !Generated(t) {
		return nil, nil
	}
	var l *record.Layout
	var err error
	switch opt.Mode {
	case record.ModeFilter:
		l, err = buildFilter(tf, opt.Explicit)
	case record.ModeEntry:
		l, err = buildEntry(t.Params, opt.MaxBytes)
	default:
		return nil, fmt.Errorf("invalid record mode %q", opt.Mode)
	}
	if err != nil || l == nil {
		return l, err
	}
	// A comment, with the exit-mode return= prefix, must fit one pcapng
	// option. Refuse an explicit request whose worst case would not; a
	// default turns itself off.
	if n := l.MaxCommentLen() + record.ReturnPrefixLen; n > record.MaxCommentBytes {
		if !opt.Explicit {
			return nil, nil
		}
		hint := "filter fewer fields"
		if opt.Mode == record.ModeEntry {
			hint = "lower --record-max"
		}
		return nil, fmt.Errorf("--record %s: worst-case comment %d bytes exceeds %d; %s", opt.Mode, n, record.MaxCommentBytes, hint)
	}
	return l, nil
}

// OmittedFields lists the argument filters and set keys that --record
// filter does not record because their member path crosses a bpf_* struct
// (hookabi.Opaque): the default layout leaves them out, and an explicit
// --record filter refuses them.
func OmittedFields(tf filter.TargetFilters) []string {
	var out []string
	for _, a := range tf.Args {
		if a.ThroughOpaque {
			out = append(out, a.ParamName)
		}
	}
	for _, s := range tf.Sets {
		for _, k := range s.Fields {
			if k.ThroughOpaque {
				out = append(out, k.ParamName)
			}
		}
	}
	return out
}

func buildFilter(tf filter.TargetFilters, explicit bool) (*record.Layout, error) {
	if omitted := OmittedFields(tf); explicit && len(omitted) > 0 {
		return nil, fmt.Errorf("--record filter: %s is inside a bpf_* struct, which is never recorded; drop that condition, or keep it with --record entry or --record none", omitted[0])
	}
	l := &record.Layout{Mode: record.ModeFilter}
	seen := map[record.Field]bool{}
	add := func(f record.Field, opaque bool) {
		key := f
		key.Name = ""
		if opaque || seen[key] {
			return
		}
		seen[key] = true
		l.Fields = append(l.Fields, f)
	}
	for _, a := range tf.Args {
		add(record.Field{Name: a.ParamName, ParamIndex: a.ParamIndex, Size: a.ParamSize, Signed: a.Signed, Deref: a.Deref, Pointer: a.Pointer, Offset: a.Offset}, a.ThroughOpaque)
	}
	for _, s := range tf.Sets {
		for _, k := range s.Fields {
			add(record.Field{Name: k.ParamName, ParamIndex: k.ParamIdx, Size: k.ParamSize, Signed: k.ParamSigned, Deref: k.Deref, Offset: k.Offset}, k.ThroughOpaque)
		}
	}
	if len(l.Fields) == 0 {
		return nil, nil
	}
	if len(l.Fields) > record.MaxFields {
		if explicit {
			return nil, fmt.Errorf("--record filter: %d fields, at most %d", len(l.Fields), record.MaxFields)
		}
		return nil, nil // default: too many fields, keep the plain layout
	}
	return l, nil
}

func buildEntry(params []attach.FuncParamInfo, maxBytes int) (*record.Layout, error) {
	if maxBytes < 0 || maxBytes > record.MaxBytesLimit {
		return nil, fmt.Errorf("--record-max %d: must be 0..%d", maxBytes, record.MaxBytesLimit)
	}
	l := &record.Layout{Mode: record.ModeEntry,
		Site: record.Scalar{ParamIndex: -1}, Status: record.Scalar{ParamIndex: -1},
		Key: record.Bytes{Name: "key", ParamIndex: -1}, Value: record.Bytes{Name: "value", ParamIndex: -1}}
	for _, p := range params {
		switch p.Name {
		case "site":
			if p.Kind == "" && p.Size == 4 {
				l.Site = record.Scalar{Name: "site", ParamIndex: p.Index, Size: 4}
			}
		case "info":
			if p.Kind == "" && p.Size == 8 {
				if !l.Site.Present() {
					l.Site = record.Scalar{Name: "info", ParamIndex: p.Index, Size: 4}
				}
				if !l.Status.Present() {
					l.Status = record.Scalar{Name: "info", ParamIndex: p.Index, Size: 8}
				}
			}
		case "status":
			if p.Kind == "" && p.Size == 8 {
				l.Status = record.Scalar{Name: "status", ParamIndex: p.Index, Size: 8}
			}
		case "key":
			l.Key = entryBytes(p, maxBytes)
		case "value":
			l.Value = entryBytes(p, maxBytes)
		}
	}
	if !l.Site.Present() && !l.Status.Present() && !l.Key.Present() && !l.Value.Present() {
		return nil, nil
	}
	return l, nil
}

// entryBytes sizes a key or value argument. A pointer's pointee size comes
// from BTF; a const void pointer (an untrusted or generic hook) takes its
// size from the hook's size decl tag (VoidSize, non-zero only on a generated
// hook), recording the raw bytes when inject-run supplied it and nothing
// otherwise.
func entryBytes(p attach.FuncParamInfo, maxBytes int) record.Bytes {
	b := record.Bytes{Name: p.Name, ParamIndex: p.Index}
	if p.Kind == "" {
		// An integer passed by value is recorded whole or not at all.
		b.Size = p.Size
		if uint32(maxBytes) >= b.Size {
			b.Len = b.Size
		}
		return b
	}
	b.Pointer = true
	ptr, ok := btf.UnderlyingType(p.Type).(*btf.Pointer)
	if !ok {
		return b
	}
	b.Type = ptr.Target
	if _, void := btf.UnderlyingType(ptr.Target).(*btf.Void); void {
		b.Size = p.VoidSize // 0 without a size tag: record nothing
	} else if size, err := btf.Sizeof(ptr.Target); err == nil && size > 0 {
		b.Size = uint32(size)
	}
	b.Len = min(b.Size, uint32(maxBytes))
	return b
}

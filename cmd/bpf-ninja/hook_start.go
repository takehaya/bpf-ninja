package main

import (
	"fmt"
	"sort"
	"strings"
)

func parseHookStarts(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, value := range values {
		name, expr, ok := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		expr = strings.TrimSpace(expr)
		if name == "@entry" {
			return nil, fmt.Errorf("--start @entry: use the positional filter for the root entry")
		}
		if !ok || name == "" || expr == "" {
			return nil, fmt.Errorf("--start requires NAME=FILTER with a hook name and nonempty filter")
		}
		if _, ok := out[name]; ok {
			return nil, fmt.Errorf("duplicate --start for hook %q", name)
		}
		out[name] = expr
	}
	return out, nil
}
func appendHookStarts(names []string, starts map[string]string) []string {
	out := append([]string(nil), names...)
	var added []string
	for name := range starts {
		found := false
		for _, n := range names {
			found = found || n == name
		}
		if !found {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	return append(out, added...)
}

package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/urfave/cli/v3"
)

// siteHooksFile is the part of an inject-run --hooks-json file that --site
// reads.
type siteHooksFile struct {
	Programs []siteHooksProg `json:"programs"`
}

type siteHooksProg struct {
	ProgID uint32 `json:"prog_id"`
	Tag    string `json:"tag"`
	Hooks  []struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		SiteParam bool   `json:"site_param"`
		Sites     []struct {
			PC    uint32 `json:"pc"`
			Label string `json:"label"`
			Kind  string `json:"kind"`
		} `json:"sites"`
	} `json:"hooks"`
}

// resolveSite finds site, a label or a pc, of program progID with kernel tag
// tag in the hooks file data read from path: the hooks that report it and
// its pc. A hook that reports it without a site parameter is refused: the
// capture filters on site.
func resolveSite(data []byte, path string, progID uint32, tag, site string) ([]string, uint32, error) {
	var file siteHooksFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, 0, fmt.Errorf("--site: %s: %w", path, err)
	}
	i := slices.IndexFunc(file.Programs, func(p siteHooksProg) bool {
		return p.ProgID == progID
	})
	if i < 0 {
		return nil, 0, fmt.Errorf("--site: %s has no program with prog_id %d", path, progID)
	}
	prog := file.Programs[i]
	if prog.Tag != tag {
		return nil, 0, fmt.Errorf("--site: %s lists prog_id %d with tag %s but the loaded program has tag %s; the file is from another load", path, progID, prog.Tag, tag)
	}
	pc, byPC := uint32(0), false
	if n, err := strconv.ParseUint(site, 10, 32); err == nil {
		pc, byPC = uint32(n), true
	}
	var hooks []string
	for _, hook := range prog.Hooks {
		for _, s := range hook.Sites {
			if s.Kind != "entry" && (byPC && s.PC == pc || !byPC && s.Label == site) {
				if !hook.SiteParam {
					return nil, 0, fmt.Errorf("--site: hook %q is a %s hook, which has no site parameter; capture it with --func %s", hook.Name, hook.Kind, hook.Name)
				}
				hooks, pc = append(hooks, hook.Name), s.PC
				break
			}
		}
	}
	if len(hooks) == 0 && !byPC {
		// A base label names every copy that carries it with a #N suffix.
		// The argument filters are ANDed and have no or, so one capture
		// cannot take several sites: name the copies to choose from.
		copies := map[uint32]string{}
		for _, hook := range prog.Hooks {
			for _, s := range hook.Sites {
				if n, ok := strings.CutPrefix(s.Label, site+"#"); ok && s.Kind != "entry" {
					if _, err := strconv.ParseUint(n, 10, 32); err == nil {
						copies[s.PC] = s.Label
					}
				}
			}
		}
		if len(copies) != 0 {
			labels := make([]string, 0, len(copies))
			for _, pc := range slices.Sorted(maps.Keys(copies)) {
				labels = append(labels, copies[pc])
			}
			if len(labels) == 1 {
				return nil, 0, fmt.Errorf("--site: %q names one site; give %s", site, labels[0])
			}
			return nil, 0, fmt.Errorf("--site: %q names %d sites; give one of %s", site, len(labels), strings.Join(labels, " "))
		}
	}
	if len(hooks) == 0 {
		return nil, 0, fmt.Errorf("--site: no site %q in program %d", site, progID)
	}
	return hooks, pc, nil
}

// expandSite turns --site and --hooks-json into --func for the hooks that
// report the site and --arg-filter site==PC, ANDed with the user's filters,
// and --no-follow.
func expandSite(cmd *cli.Command, infos []*attach.ProgInfo) error {
	site, path := cmd.String("site"), cmd.String("hooks-json")
	switch {
	case site == "" && path == "":
		return nil
	case site == "":
		return fmt.Errorf("--hooks-json needs --site")
	case path == "":
		return fmt.Errorf("--site needs --hooks-json, the file inject-run --hooks-json wrote")
	case len(cmd.IntSlice("prog-id")) != 1 || len(infos) != 1:
		return fmt.Errorf("--site needs exactly one -p")
	case len(cmd.StringSlice("func")) != 0:
		return fmt.Errorf("--site selects the hook itself; do not combine it with --func")
	}
	info, err := infos[0].Program.Info()
	if err != nil {
		return fmt.Errorf("--site: program %d: %w", infos[0].ProgID, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("--site: %w", err)
	}
	hooks, pc, err := resolveSite(data, path, infos[0].ProgID, info.Tag, site)
	if err != nil {
		return err
	}
	for _, hook := range hooks {
		if err := cmd.Set("func", hook); err != nil {
			return err
		}
	}
	// The pc names the site in this load only; a reload may put another
	// call there, so the capture does not follow the hook.
	if err := cmd.Set("no-follow", "true"); err != nil {
		return err
	}
	return cmd.Set("arg-filter", fmt.Sprintf("site==%d", pc))
}

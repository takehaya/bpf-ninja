// `xdp-ninja set` subcommands: manage pinned-map match sets by field
// name. BTF carries the key schema, so nobody hand-assembles zero-padded
// native-endian hex the way `bpftool map update key hex ...` requires.
package main

import (
	"context"
	"fmt"
	"math"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/takehaya/xdp-ninja/internal/setmap"
)

var setCommand = &cli.Command{
	Name:  "set",
	Usage: "manage pinned-map match sets (see --set / --arg-filter @NAME)",
	Description: `A match set is a pinned BPF hash map whose KEY is the value (or
composite of values) to match and whose value is a small tag. Capture
references it with --set NAME=/path + --arg-filter @NAME; entries added
or deleted here take effect immediately, without re-attaching.

Examples:
  xdp-ninja set create /sys/fs/bpf/flows --key "imsi:u64,teid:u32"
  xdp-ninja set add    /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039 tag=1
  xdp-ninja set del    /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039
  xdp-ninja set list   /sys/fs/bpf/flows
  xdp-ninja set schema /sys/fs/bpf/flows
  xdp-ninja set resize /sys/fs/bpf/flows --max-entries 4096`,
	Commands: []*cli.Command{setCreateCmd, setAddCmd, setDelCmd, setListCmd, setSchemaCmd, setResizeCmd},
}

var setCreateCmd = &cli.Command{
	Name:      "create",
	Usage:     "create + pin a BTF-carrying hash set map",
	ArgsUsage: "<pin-path>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "key", Required: true,
			Usage: "key schema, e.g. \"imsi:u64,teid:u32\" (types: u8/u16/u32/u64, or ipv6 for a 16-byte address / SRv6 SID; numeric fields align to their width, ipv6 to 8)",
		},
		&cli.StringFlag{
			Name: "value", Value: "tag:u32",
			Usage: "value schema (default a u32 tag)",
		},
		&cli.IntFlag{
			Name: "max-entries", Value: 1024,
			Usage: "map capacity",
		},
	},
	Action: func(_ context.Context, cmd *cli.Command) error {
		path, err := setPathArg(cmd)
		if err != nil {
			return err
		}
		maxEntries := cmd.Int("max-entries")
		if maxEntries <= 0 || maxEntries > math.MaxUint32 {
			return fmt.Errorf("--max-entries must be in 1..%d, got %d", math.MaxUint32, maxEntries)
		}
		if err := setmap.Create(path, cmd.String("key"), cmd.String("value"), uint32(maxEntries)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created %s (key: %s, value: %s, max_entries: %d)\n",
			path, cmd.String("key"), cmd.String("value"), cmd.Int("max-entries"))
		return nil
	},
}

var setResizeCmd = &cli.Command{
	Name:      "resize",
	Usage:     "change a set's capacity (copies entries into a new map, swaps the pin)",
	ArgsUsage: "<pin-path>",
	Description: `BPF maps cannot change max_entries in place, so resize creates a new
map with the same key/value BTF, copies every entry, and atomically
replaces the pin. A running capture keeps the old map from attach time;
the new capacity takes effect from the next attach. Entries added
between the copy and the swap are lost, so resize while no writer is
active.`,
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name: "max-entries", Required: true,
			Usage: "new map capacity",
		},
	},
	Action: func(_ context.Context, cmd *cli.Command) error {
		path, err := setPathArg(cmd)
		if err != nil {
			return err
		}
		maxEntries := cmd.Int("max-entries")
		if maxEntries <= 0 || maxEntries > math.MaxUint32 {
			return fmt.Errorf("--max-entries must be in 1..%d, got %d", math.MaxUint32, maxEntries)
		}
		oldMax, copied, err := setmap.Resize(path, uint32(maxEntries))
		if err != nil {
			return err
		}
		if oldMax == uint32(maxEntries) {
			fmt.Fprintf(os.Stderr, "%s already has max_entries %d, nothing to do\n", path, oldMax)
			return nil
		}
		fmt.Fprintf(os.Stderr, "resized %s (max_entries: %d -> %d, copied %d entries)\n",
			path, oldMax, maxEntries, copied)
		return nil
	},
}

var setAddCmd = &cli.Command{
	Name:      "add",
	Usage:     "insert or update one entry (full key required)",
	ArgsUsage: "<pin-path> field=value ... [tag=N]",
	Action: func(_ context.Context, cmd *cli.Command) error {
		def, fields, tag, err := setOpenWithFields(cmd)
		if err != nil {
			return err
		}
		defer def.Close()
		return def.Add(fields, tag)
	},
}

var setDelCmd = &cli.Command{
	Name:      "del",
	Usage:     "delete one entry (full key required)",
	ArgsUsage: "<pin-path> field=value ...",
	Action: func(_ context.Context, cmd *cli.Command) error {
		def, fields, _, err := setOpenWithFields(cmd)
		if err != nil {
			return err
		}
		defer def.Close()
		return def.Delete(fields)
	},
}

var setListCmd = &cli.Command{
	Name:      "list",
	Usage:     "print all entries as field=value lines",
	ArgsUsage: "<pin-path>",
	Action: func(_ context.Context, cmd *cli.Command) error {
		def, err := setOpen(cmd)
		if err != nil {
			return err
		}
		defer def.Close()
		return def.List(os.Stdout)
	},
}

var setSchemaCmd = &cli.Command{
	Name:      "schema",
	Usage:     "print the key layout resolved from the map's BTF",
	ArgsUsage: "<pin-path>",
	Action: func(_ context.Context, cmd *cli.Command) error {
		def, err := setOpen(cmd)
		if err != nil {
			return err
		}
		defer def.Close()
		def.Schema(os.Stdout)
		return nil
	},
}

func setPathArg(cmd *cli.Command) (string, error) {
	if cmd.Args().Len() < 1 {
		return "", fmt.Errorf("missing pinned map path (e.g. /sys/fs/bpf/flows)")
	}
	return cmd.Args().First(), nil
}

func setOpen(cmd *cli.Command) (*setmap.Definition, error) {
	path, err := setPathArg(cmd)
	if err != nil {
		return nil, err
	}
	return setmap.Open(path)
}

// setOpenWithFields opens the map and parses the trailing field=value
// args (with the optional tag=N split off).
func setOpenWithFields(cmd *cli.Command) (*setmap.Definition, map[string]string, uint64, error) {
	def, err := setOpen(cmd)
	if err != nil {
		return nil, nil, 0, err
	}
	fields, tag, hasTag, err := setmap.ParseFieldValues(cmd.Args().Tail())
	if err != nil {
		def.Close()
		return nil, nil, 0, err
	}
	if !hasTag {
		tag = 1 // presence marker
	}
	return def, fields, tag, nil
}

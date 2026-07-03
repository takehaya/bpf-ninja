// `xdp-ninja set` subcommands: manage pinned-map match sets by field
// name. BTF carries the key schema, so nobody hand-assembles zero-padded
// native-endian hex the way `bpftool map update key hex ...` requires.
package main

import (
	"context"
	"fmt"
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
  xdp-ninja set add    /sys/fs/bpf/flows imsi=901040010000005 teid=0x3039 tag=1
  xdp-ninja set del    /sys/fs/bpf/flows imsi=901040010000005 teid=0x3039
  xdp-ninja set list   /sys/fs/bpf/flows
  xdp-ninja set schema /sys/fs/bpf/flows`,
	Commands: []*cli.Command{setCreateCmd, setAddCmd, setDelCmd, setListCmd, setSchemaCmd},
}

var setCreateCmd = &cli.Command{
	Name:      "create",
	Usage:     "create + pin a BTF-carrying hash set map",
	ArgsUsage: "<pin-path>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "key", Required: true,
			Usage: "key schema, e.g. \"imsi:u64,teid:u32\" (types: u8/u16/u32/u64; fields are laid out with natural alignment)",
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
		if err := setmap.Create(path, cmd.String("key"), cmd.String("value"), uint32(cmd.Int("max-entries"))); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created %s (key: %s, value: %s, max_entries: %d)\n",
			path, cmd.String("key"), cmd.String("value"), cmd.Int("max-entries"))
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
func setOpenWithFields(cmd *cli.Command) (*setmap.Definition, map[string]uint64, uint64, error) {
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

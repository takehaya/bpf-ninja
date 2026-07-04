// xdp-ninja merge: reconcile the per-CPU tag shard files left by a
// --split-by-tag capture into one pcap-ng per tag. A clean shutdown merges
// automatically; this subcommand handles the case where the capture was
// killed and the <base>.cpuN.<tag> files are still lying around.

package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/takehaya/xdp-ninja/internal/output"
)

var mergeFlags = []cli.Flag{
	&cli.StringFlag{
		Name: "base", Aliases: []string{"b"},
		Usage: "the -w base path used during capture (e.g. out.pcap); its out.cpuN.<tag> shards are merged into out.<tag>.pcap",
	},
	&cli.BoolFlag{
		Name:  "fexit",
		Usage: "the shards came from --mode exit / tc-exit (they carry a per-action pcap-ng interface); set this so the merged file keeps the same interfaces",
	},
}

var mergeCommand = &cli.Command{
	Name:  "merge",
	Usage: "merge leftover per-CPU tag shards from --split-by-tag into one pcap-ng per tag",
	Description: `Merge the per-CPU tag shard files a --split-by-tag capture leaves behind
(<base>.cpuN.<tag>) into a single time-ordered pcap-ng per tag
(<base>.<tag>). A clean shutdown does this automatically; run this when the
capture was killed and the per-CPU files still need reconciling. The shard
files are left in place.

Examples:
  xdp-ninja merge --base out.pcap
  xdp-ninja merge -b out.pcap --fexit`,
	Flags:  mergeFlags,
	Action: runMerge,
}

func runMerge(_ context.Context, cmd *cli.Command) error {
	base := cmd.String("base")
	if base == "" {
		return fmt.Errorf("--base/-b required")
	}
	if err := output.MergeTagShards(base, cmd.Bool("fexit")); err != nil {
		return fmt.Errorf("merging tag shards for %s: %w", base, err)
	}
	return nil
}

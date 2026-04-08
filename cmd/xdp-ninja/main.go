package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/capture"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/internal/output"
	"github.com/takehaya/xdp-ninja/internal/program"
)

// Set via -ldflags "-X main.version=... -X main.commit=... -X main.date=... -X main.builtBy=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name: "interface", Aliases: []string{"i"},
		Usage: "network interface to capture on",
	},
	&cli.IntFlag{
		Name: "prog-id", Aliases: []string{"p"},
		Usage: "BPF program ID to attach to (use instead of -i for multi-prog setups)",
	},
	&cli.StringFlag{
		Name: "write", Aliases: []string{"w"},
		Usage: "write packets to pcap file instead of stdout",
	},
	&cli.StringFlag{
		Name: "mode", Value: "entry",
		Usage: "capture point: entry (before XDP) or exit (after XDP)",
	},
	&cli.IntFlag{
		Name: "count", Aliases: []string{"c"},
		Usage: "exit after capturing N packets (0 = unlimited)",
	},
	&cli.StringFlag{
		Name:  "func",
		Usage: "attach to a specific __noinline subfunction (by BTF name) instead of the entry function",
	},
	&cli.BoolFlag{
		Name:  "list-funcs",
		Usage: "list available BTF functions in the target program and exit",
	},
	&cli.BoolFlag{
		Name:  "list-progs",
		Usage: "list tail call targets reachable from the target program and exit",
	},
	&cli.StringSliceFlag{
		Name:  "arg-filter",
		Usage: "filter by function argument value (requires --func); format: param=value, param>=val, param<=val, param=min..max",
	},
	&cli.BoolFlag{
		Name:  "list-params",
		Usage: "list filterable parameters for the target function (requires --func) and exit",
	},
	&cli.BoolFlag{
		Name: "verbose", Aliases: []string{"v"},
		Usage: "verbose output to stderr",
	},
}

func init() {
	cli.VersionFlag = &cli.BoolFlag{
		Name:        "version",
		Aliases:     []string{"V"},
		Usage:       "print the version",
		HideDefault: true,
		Local:       true,
	}
}

func main() {
	app := &cli.Command{
		Name:      "xdp-ninja",
		Version:   fmt.Sprintf("%s, commit %s, built at %s, built by %s", version, commit, date, builtBy),
		Usage:     "capture packets before or after XDP processing",
		ArgsUsage: "[filter expression]",
		Description: `Outputs pcap (pcapng) to stdout. Pipe to tcpdump, wireshark, etc.
To capture both before and after, run two instances with different --mode.

Examples:
  xdp-ninja -i eth0 | tcpdump -n -r -
  xdp-ninja -i eth0 "host 10.0.0.1" | tcpdump -r -
  xdp-ninja -i eth0 --mode exit | tcpdump -r -
  xdp-ninja -p 42 | tcpdump -n -r -
  xdp-ninja -i eth0 -w out.pcap`,
		Flags:                 flags,
		Action:                run,
		EnableShellCompletion: true,
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	mode := cmd.String("mode")
	var isFexit bool
	switch mode {
	case "entry":
	case "exit":
		isFexit = true
	default:
		return fmt.Errorf("invalid mode %q: must be entry or exit", mode)
	}

	info, err := findTarget(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = info.Program.Close() }()

	// --list-progs: show tail call targets, then exit
	if cmd.Bool("list-progs") {
		fmt.Fprintf(os.Stderr, "id=%-6d %s\n", info.ProgID, info.FuncName)

		targets, err := attach.ListTailCallTargets(info.Program)
		if err != nil {
			return err
		}
		for _, t := range targets {
			fmt.Fprintf(os.Stderr, "id=%-6d %s (tailcall[%d])\n", t.ProgID, t.ProgName, t.Index)
		}
		return nil
	}

	// --list-funcs: print available BTF functions and exit
	if cmd.Bool("list-funcs") {
		funcs, err := attach.ListFuncs(info.Program)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "BTF functions in program (id=%d):\n", info.ProgID)
		for _, f := range funcs {
			fmt.Fprintf(os.Stderr, "  %-40s [%s]\n", f.Name, f.Linkage)
		}
		return nil
	}

	// --func: override target function name.
	// Open BTF once and share across validation and parameter extraction.
	funcName := cmd.String("func")
	needParams := cmd.Bool("list-params") || len(cmd.StringSlice("arg-filter")) > 0
	var params []attach.FuncParamInfo
	if funcName != "" {
		spec, err := attach.BTFSpec(info.Program)
		if err != nil {
			return fmt.Errorf("program (id=%d): %w", info.ProgID, err)
		}
		if err := attach.ValidateSubfuncFromSpec(spec, info.ProgID, funcName); err != nil {
			return err
		}
		logVerbose(cmd, "overriding entry function with --func %q", funcName)
		info.FuncName = funcName

		if needParams {
			params, err = attach.GetFuncParamsFromSpec(spec, funcName)
			if err != nil {
				return err
			}
		}
	} else if needParams {
		if cmd.Bool("list-params") {
			return fmt.Errorf("--list-params requires --func")
		}
		return fmt.Errorf("--arg-filter requires --func")
	}

	// --list-params: show filterable parameters, then exit
	if cmd.Bool("list-params") {
		fmt.Fprintf(os.Stderr, "Filterable parameters for %s (id=%d):\n", funcName, info.ProgID)
		if len(params) == 0 {
			fmt.Fprintf(os.Stderr, "  (none - only integer parameters after the first argument are supported)\n")
		}
		for _, p := range params {
			signStr := "unsigned"
			if p.Signed {
				signStr = "signed"
			}
			fmt.Fprintf(os.Stderr, "  %-20s [%d bytes, %s, arg index %d]\n", p.Name, p.Size, signStr, p.Index)
		}
		return nil
	}

	// --arg-filter: parse and validate argument filters
	var argFilters []filter.ArgFilter
	if argFilterExprs := cmd.StringSlice("arg-filter"); len(argFilterExprs) > 0 {
		var err error
		argFilters, err = filter.ParseAndValidateFilters(argFilterExprs, params)
		if err != nil {
			return err
		}
		for _, f := range argFilters {
			logVerbose(cmd, "arg filter: %s", f.String())
		}
	}

	filterExpr := strings.Join(cmd.Args().Slice(), " ")
	logVerbose(cmd, "found XDP program %q (id=%d)", info.FuncName, info.ProgID)
	if filterExpr != "" {
		logVerbose(cmd, "filter: %s", filterExpr)
	}

	probe, err := loadProbe(isFexit, info, filterExpr, argFilters)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := probe.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing probe: %v\n", cerr)
		}
	}()

	writer, err := output.NewWriter(cmd.String("write"), isFexit)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := writer.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing writer: %v\n", cerr)
		}
	}()

	reader, err := capture.NewReader(probe.EventsMap, 256*1024)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	label := fmt.Sprintf("prog %q id=%d", info.FuncName, info.ProgID)
	if info.IfaceName != "" {
		label = fmt.Sprintf("%s on %s", label, info.IfaceName)
	}
	fmt.Fprintf(os.Stderr, "capturing (%s, mode=%s)...\n", label, mode)

	return captureLoop(cmd, reader, writer)
}

func findTarget(cmd *cli.Command) (*attach.XDPInfo, error) {
	ifaceName := cmd.String("interface")
	progID := cmd.Int("prog-id")

	if ifaceName != "" && progID != 0 {
		return nil, fmt.Errorf("specify either -i or -p, not both")
	}
	if ifaceName == "" && progID == 0 {
		return nil, fmt.Errorf("specify -i <interface> or -p <prog-id>")
	}

	if progID != 0 {
		return attach.FindXDPProgramByID(uint32(progID))
	}
	return attach.FindXDPProgram(ifaceName)
}

func loadProbe(isFexit bool, info *attach.XDPInfo, filterExpr string, argFilters []filter.ArgFilter) (*program.Probe, error) {
	if isFexit {
		return program.LoadExit(info.Program, info.FuncName, filterExpr, argFilters)
	}
	return program.LoadEntry(info.Program, info.FuncName, filterExpr, argFilters)
}

func captureLoop(cmd *cli.Command, reader *capture.Reader, writer *output.Writer) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	go func() {
		<-sig
		_ = reader.Close()
	}()

	count := int(cmd.Int("count"))
	captured := 0

	for {
		pkt, err := reader.Read()
		if err != nil {
			if errors.Is(err, capture.ErrClosed) {
				break
			}
			logVerbose(cmd, "warning: %v", err)
			continue
		}

		if err := writer.Write(pkt); err != nil {
			fmt.Fprintf(os.Stderr, "warning: write error: %v\n", err)
		}

		captured++
		if count > 0 && captured >= count {
			break
		}
	}

	fmt.Fprintf(os.Stderr, "\n%d packets captured\n", captured)
	return nil
}

func logVerbose(cmd *cli.Command, format string, args ...any) {
	if cmd.Bool("verbose") {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

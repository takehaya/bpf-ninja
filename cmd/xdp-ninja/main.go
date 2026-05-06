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
		Usage: "capture point: entry / exit (XDP fentry/fexit observer), tc-entry / tc-exit (tc clsact fentry/fexit observer), or xdp (attach as native XDP)",
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
		Name:  "cbpf",
		Usage: "use the legacy tcpdump/cBPF filter syntax (compiled via cbpfc); default is the built-in DSL",
	},
	&cli.BoolFlag{
		Name:  "dsl-help",
		Usage: "print the xdp-ninja DSL grammar + bundled protocol list and exit (pass a protocol name as positional arg to inspect its fields, e.g. `--dsl-help ipv4`)",
	},
	&cli.StringFlag{
		Name:  "dump-asm",
		Usage: "compile the filter and print the resulting eBPF asm without loading; values: filter (kunai/cbpfc Main + Callbacks) | full (wrapped tracing program)",
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
		Usage:     "capture packets at XDP time (fentry/fexit observer or standalone XDP)",
		ArgsUsage: "[filter expression]",
		Description: `Outputs pcap (pcapng) to stdout. Pipe to tcpdump, wireshark, etc.

Modes (--mode):
  entry     fentry on the existing XDP — observe packets before the program runs (default)
  exit      fexit on the existing XDP — observe action returned (filter on XDP_PASS/DROP/...)
  tc-entry  fentry on a tc clsact program (specify target via -p)
  tc-exit   fexit on a tc clsact program (filter on TC_ACT_OK/SHOT/...)
  xdp       attach as the primary XDP on the netdev (no existing XDP needed)

Examples:
  xdp-ninja -i eth0 | tcpdump -n -r -
  xdp-ninja -i eth0 "host 10.0.0.1" | tcpdump -r -
  xdp-ninja -i eth0 --mode exit | tcpdump -r -
  xdp-ninja --mode xdp -i eth0 "tcp port 443" | tcpdump -r -
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
	if cmd.Bool("dsl-help") {
		// Positional arg, when present, names a bundled protocol
		// whose fields the user wants to inspect.
		if args := cmd.Args().Slice(); len(args) > 0 {
			return printProtoHelp(os.Stdout, args[0])
		}
		return printDSLHelp(os.Stdout)
	}

	mode := cmd.String("mode")
	var isFexit, isXDPNative, isTC bool
	switch mode {
	case "entry":
	case "exit":
		isFexit = true
	case "tc-entry":
		isTC = true
	case "tc-exit":
		isTC = true
		isFexit = true
	case "xdp":
		isXDPNative = true
	default:
		return fmt.Errorf("invalid mode %q: must be entry, exit, tc-entry, tc-exit, or xdp", mode)
	}

	if scope := cmd.String("dump-asm"); scope != "" {
		filterExpr := strings.Join(cmd.Args().Slice(), " ")
		useDSL, err := resolveFilterSyntax(cmd)
		if err != nil {
			return err
		}
		return program.DumpAsm(os.Stdout, program.DumpScope(scope), filterExpr, useDSL, mode)
	}

	if isXDPNative {
		return runXDPNative(cmd)
	}

	info, err := findTarget(cmd, isTC)
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

	useDSL, err := resolveFilterSyntax(cmd)
	if err != nil {
		return err
	}
	probe, err := loadProbe(isFexit, info, filterExpr, argFilters, useDSL)
	if err != nil {
		return err
	}

	label := fmt.Sprintf("prog %q id=%d", info.FuncName, info.ProgID)
	if info.IfaceName != "" {
		label = fmt.Sprintf("%s on %s", label, info.IfaceName)
	}
	return runCaptureLoop(cmd, probe, isFexit, fmt.Sprintf("%s, mode=%s", label, mode))
}

// resolveFilterSyntax returns whether to use the DSL path (default)
// or the legacy cBPF path (--cbpf).
func resolveFilterSyntax(cmd *cli.Command) (useDSL bool, err error) {
	useCBPF := cmd.Bool("cbpf")
	if useCBPF {
		fmt.Fprintln(os.Stderr, "warning: --cbpf selects the legacy cBPF path; prefer the default DSL.")
	}
	return !useCBPF, nil
}

// runCaptureLoop wires a loaded probe to the perf reader + pcap
// writer and pumps the capture loop until SIGINT/SIGTERM. Owns the
// teardown order: probe → writer → reader.
func runCaptureLoop(cmd *cli.Command, probe *program.Probe, isFexit bool, label string) error {
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

	fmt.Fprintf(os.Stderr, "capturing (%s)...\n", label)
	return captureLoop(cmd, reader, writer)
}

// runXDPNative handles --mode xdp: xdp-ninja is itself the XDP
// program on the netdev (no fentry/fexit piggybacking).
func runXDPNative(cmd *cli.Command) error {
	if err := validateXDPNativeFlags(cmd); err != nil {
		return err
	}

	filterExpr := strings.Join(cmd.Args().Slice(), " ")
	useDSL, err := resolveFilterSyntax(cmd)
	if err != nil {
		return err
	}

	ifaceName := cmd.String("interface")
	state, err := attach.InspectInterface(ifaceName)
	if err != nil {
		return err
	}

	if state.Existing != nil {
		return fmt.Errorf(
			"interface %s already has XDP program (id=%d, mode=%s); use --mode entry to observe it via fentry, or detach the existing program first",
			ifaceName, state.Existing.ProgID, state.Existing.Mode,
		)
	}

	logVerbose(cmd, "attaching xdp-ninja as native XDP on %s (filter: %s)", ifaceName, filterExpr)

	probe, err := program.LoadXDPNative(state, filterExpr, useDSL)
	if err != nil {
		return err
	}
	return runCaptureLoop(cmd, probe, false, fmt.Sprintf("xdp-native on %s", ifaceName))
}

// validateXDPNativeFlags rejects flags that don't apply to --mode xdp
// (entry/exit-only flags) so the user gets a clear error before any
// netlink lookup.
func validateXDPNativeFlags(cmd *cli.Command) error {
	if cmd.String("interface") == "" {
		return fmt.Errorf("--mode xdp requires -i <interface>")
	}
	if cmd.Int("prog-id") != 0 {
		return fmt.Errorf("--mode xdp does not accept -p (the program is xdp-ninja itself, not an existing one)")
	}
	if cmd.String("func") != "" {
		return fmt.Errorf("--func is only valid with --mode entry/exit (no BTF subfunction concept in xdp-native)")
	}
	if len(cmd.StringSlice("arg-filter")) > 0 {
		return fmt.Errorf("--arg-filter is only valid with --mode entry/exit (no tracing args in xdp-native)")
	}
	if cmd.Bool("list-funcs") || cmd.Bool("list-progs") || cmd.Bool("list-params") {
		return fmt.Errorf("--list-* flags are only valid with --mode entry/exit")
	}
	return nil
}

func findTarget(cmd *cli.Command, isTC bool) (*attach.ProgInfo, error) {
	ifaceName := cmd.String("interface")
	progID := cmd.Int("prog-id")

	if ifaceName != "" && progID != 0 {
		return nil, fmt.Errorf("specify either -i or -p, not both")
	}
	if ifaceName == "" && progID == 0 {
		return nil, fmt.Errorf("specify -i <interface> or -p <prog-id>")
	}

	if isTC {
		// tc clsact targets are addressed by program ID — no
		// interface-based clsact qdisc walk wired up yet.
		if ifaceName != "" {
			return nil, fmt.Errorf("--mode tc-* requires -p <prog-id>; interface-based tc target lookup is not implemented")
		}
		return attach.FindBPFProgramByID(uint32(progID))
	}

	if progID != 0 {
		return attach.FindXDPProgramByID(uint32(progID))
	}
	return attach.FindXDPProgram(ifaceName)
}

func loadProbe(isFexit bool, info *attach.ProgInfo, filterExpr string, argFilters []filter.ArgFilter, useDSL bool) (*program.Probe, error) {
	if isFexit {
		return program.LoadExit(info.Program, info.FuncName, filterExpr, argFilters, useDSL)
	}
	return program.LoadEntry(info.Program, info.FuncName, filterExpr, argFilters, useDSL)
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

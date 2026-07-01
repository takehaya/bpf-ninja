package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
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
		Usage: "list programs reachable from the target: tail calls + CPUMAP/DEVMAP/DEVMAP_HASH redirect targets (followed transitively), then exit",
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
	&cli.IntFlag{
		Name:  "snaplen",
		Value: 0,
		Usage: fmt.Sprintf("force the per-packet capture length (0 = use the DSL capture clause's value, falling back to the host default of %d bytes)", program.DefaultCapLen),
	},
	&cli.BoolFlag{
		Name:  "null-output",
		Usage: "skip pcap-ng emission and just count packets (bench / profiling)",
	},
	&cli.StringFlag{
		Name:  "cpuprofile",
		Usage: "write Go cpu profile to file (bench / debugging)",
	},
	&cli.BoolFlag{
		Name:  "no-async-preempt-off",
		Usage: "keep Go's SIGURG-based goroutine preemption enabled (diagnostic opt-out)",
	},
	&cli.BoolFlag{
		Name:  "bench-drop",
		Usage: "(--mode xdp only) return XDP_DROP after capturing instead of XDP_PASS, bypassing kernel skb-create / IP drop path. Bench-only; production should leave this off",
	},
	&cli.BoolFlag{
		Name:  "no-cpu-affinity",
		Usage: "disable pinning each per-shard ringbuf reader to its producer CPU (diagnostic opt-out)",
	},
	&cli.IntFlag{
		Name:  "ringbuf-size",
		Value: 64,
		Usage: "total ringbuf capacity in MiB (power of two); in sharded modes split evenly across CPUs",
	},
	&cli.BoolFlag{
		Name:  "legacy-timestamp",
		Usage: "use a per-batch userland time.Now() instead of the per-packet kernel bpf_ktime_get_ns() timestamp",
	},
	&cli.BoolFlag{
		Name:  "raw-dump",
		Usage: "dump ringbuf records verbatim to per-CPU .raw files; reconstruct standard pcap-ng offline via `xdp-ninja convert`",
	},
	&cli.BoolFlag{
		Name:  "fast-reader",
		Usage: "use the in-tree mmap+atomic batch ringbuf reader instead of cilium/ebpf's per-record API; supported in both --raw-dump and pcap-ng paths",
	},
	&cli.BoolFlag{
		Name:  "no-wakeup",
		Usage: "set BPF_RB_NO_WAKEUP on every ringbuf submit (saves eventfd writes on the BPF side; safe only with --fast-reader since the slow path needs wakeups)",
	},
	&cli.BoolFlag{
		Name:  "busy-poll",
		Usage: "spin the fast-reader shard goroutines on ReadBatch instead of blocking in epoll_wait; the consumer never sleeps so it drains continuously and needs no wakeup. burns a core per shard. requires --fast-reader; pair with --no-wakeup",
	},
	&cli.IntFlag{
		Name:  "rx-cores",
		Value: 0,
		Usage: "split-core capture: if >0, RX/capture is assumed confined to cores 0..N-1 (set the NIC to N queues yourself via `ethtool -L combined N`); xdp-ninja runs N consumer goroutines pinned to cores N..2N-1, off the RX softirqs. pair with --busy-poll --no-wakeup",
	},
	&cli.IntFlag{
		Name:  "in-memory-buffer",
		Value: 0,
		Usage: "if >0, per-shard raw-dump buffer size in MiB; bytes held in pre-touched Go heap until Close (bypasses write(2) + tmpfs page-fault in the hot path; raw-dump only)",
	},
	&cli.BoolFlag{
		Name:  "rx-hwts",
		Usage: "use NIC hardware timestamps (bpf_xdp_metadata_rx_timestamp kfunc, Linux 6.8+); --mode xdp only; software fallback if kfunc / driver unsupported",
	},
	&cli.BoolFlag{
		Name:  "observer-prefetch",
		Usage: "force the fentry/fexit filter to probe_read the full 512-byte scratch regardless of the chain's actual prefix needs. Trades a per-packet helper-CPU cost for warming the ice driver's L1 dcache; on prod_tx_reflect-style targets this accelerates the observed XDP program by ~70% (see docs/ja/r12-fentry-prefetch-finding.md). Default off — most deployments prefer lower observer CPU",
	},
	&cli.IntFlag{
		Name:  "latency-sample-period",
		Value: 0,
		Usage: "if >0, sample every Nth ringbuf record's BPF-submit→reader-read latency per shard. Samples land in --latency-sample-output (default stderr summary) for offline percentile analysis. Raw-dump path only",
	},
	&cli.StringFlag{
		Name:  "latency-sample-output",
		Value: "",
		Usage: "tsv path to dump latency samples (one int64 ns per line). Empty = print summary (p50/p90/p99/p99.9/p99.99/max) to stderr",
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

// ensureAsyncPreemptDisabled re-execs the process with
// GODEBUG=asyncpreemptoff=1 unless already set or --no-async-preempt-off
// is on argv. SIGURG-driven preemption otherwise dominates CPU when the
// per-CPU ringbuf reader goroutines run tight loops without natural
// yield points; this loads the equivalent setting before any
// goroutines start. The flag scan is intentionally simple — it runs
// before cli/v3 parses args.
func ensureAsyncPreemptDisabled() {
	for _, a := range os.Args[1:] {
		if a == "--no-async-preempt-off" {
			return
		}
	}
	debug := os.Getenv("GODEBUG")
	if strings.Contains(debug, "asyncpreemptoff=1") {
		return
	}

	var newDebug string
	if debug == "" {
		newDebug = "asyncpreemptoff=1"
	} else {
		newDebug = "asyncpreemptoff=1," + debug
	}
	env := os.Environ()
	replaced := false
	for i, e := range env {
		if strings.HasPrefix(e, "GODEBUG=") {
			env[i] = "GODEBUG=" + newDebug
			replaced = true
			break
		}
	}
	if !replaced {
		env = append(env, "GODEBUG="+newDebug)
	}
	exe, err := os.Executable()
	if err != nil {
		// Fall through silently; the user just loses the perf win,
		// not correctness.
		return
	}
	_ = syscall.Exec(exe, os.Args, env)
}

func main() {
	ensureAsyncPreemptDisabled()
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
  xdp-ninja -i eth0 "eth/ipv4[dst==10.0.0.1]" | tcpdump -r -
  xdp-ninja -i eth0 --mode exit | tcpdump -r -
  xdp-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]" | tcpdump -r -
  xdp-ninja --cbpf --mode xdp -i eth0 "tcp port 443" | tcpdump -r -   # legacy pcap syntax
  xdp-ninja -p 42 | tcpdump -n -r -
  xdp-ninja -i eth0 -w out.pcap`,
		Flags:                 flags,
		Action:                run,
		Commands:              []*cli.Command{convertCommand},
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

	if path := cmd.String("cpuprofile"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("cpuprofile: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("cpuprofile start: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	capture.LegacyTimestamp = cmd.Bool("legacy-timestamp")
	capture.DisableCPUAffinity = cmd.Bool("no-cpu-affinity")
	capture.BusyPoll = cmd.Bool("busy-poll")
	if capture.BusyPoll && !cmd.Bool("fast-reader") {
		return fmt.Errorf("--busy-poll requires --fast-reader (it spins the in-tree fast reader)")
	}
	capture.SplitCoreRX = int(cmd.Int("rx-cores"))
	if capture.SplitCoreRX > 0 && !cmd.Bool("fast-reader") {
		return fmt.Errorf("--rx-cores requires --fast-reader (split-core mode only applies to the in-tree fast reader)")
	}
	if mib := cmd.Int("ringbuf-size"); mib > 0 {
		sz := uint32(mib) * 1024 * 1024
		if sz&(sz-1) != 0 {
			return fmt.Errorf("--ringbuf-size %d MiB is not a power of two", mib)
		}
		program.RingbufSize = sz
	}
	if cmd.Bool("no-wakeup") {
		if !cmd.Bool("fast-reader") {
			return fmt.Errorf("--no-wakeup requires --fast-reader (the slow ringbuf path would hang without wakeups)")
		}
		program.RingbufSubmitFlags = program.BPF_RB_NO_WAKEUP
	}
	if mib := cmd.Int("in-memory-buffer"); mib > 0 {
		if !cmd.Bool("raw-dump") {
			return fmt.Errorf("--in-memory-buffer requires --raw-dump")
		}
	}
	if cmd.Bool("rx-hwts") {
		if cmd.String("mode") != "xdp" {
			return fmt.Errorf("--rx-hwts requires --mode xdp (kfunc only available on XDP-native)")
		}
		if err := program.ResolveHWTimestampKfunc(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: --rx-hwts requested but kfunc unavailable (%v); falling back to software bpf_ktime_get_ns\n", err)
		} else {
			// ice xdp_metadata_rx_timestamp returns wall-clock-aligned
			// ns (PHC initialised to system time at driver load), so
			// ParseRawSample must NOT add the monotonic→wall offset.
			capture.WallOffsetNs = 0
		}
	}

	if snaplen := cmd.Int("snaplen"); snaplen > 0 {
		program.SnaplenOverride = int(snaplen)
	}
	if cmd.Bool("observer-prefetch") {
		program.ObserverPrefetch = true
	}
	if period := cmd.Int("latency-sample-period"); period > 0 {
		capture.LatencySamplePeriod = int64(period)
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

	// --list-progs: show reachable programs (tail calls +
	// CPUMAP/DEVMAP/DEVMAP_HASH redirect targets, followed
	// transitively), then exit
	if cmd.Bool("list-progs") {
		fmt.Fprintf(os.Stderr, "id=%-6d %s\n", info.ProgID, info.FuncName)

		progs, err := attach.WalkReachablePrograms(info.Program, info.ProgID)
		if err != nil {
			return err
		}
		byParent := map[uint32][]attach.ReachableProgram{}
		for _, p := range progs {
			byParent[p.ParentID] = append(byParent[p.ParentID], p)
		}
		var printTree func(parent uint32, indent string)
		printTree = func(parent uint32, indent string) {
			for _, c := range byParent[parent] {
				fmt.Fprintf(os.Stderr, "%sid=%-6d %s (%s[%s])\n",
					indent, c.ProgID, c.ProgName, c.Via, formatKeyRanges(c.Keys))
				printTree(c.ProgID, indent+"  ")
			}
		}
		printTree(info.ProgID, "  ")
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
	printProbeWarnings(probe)

	label := fmt.Sprintf("prog %q id=%d", info.FuncName, info.ProgID)
	if info.IfaceName != "" {
		label = fmt.Sprintf("%s on %s", label, info.IfaceName)
	}
	return runCaptureLoop(cmd, probe, isFexit, fmt.Sprintf("%s, mode=%s", label, mode))
}

// printProbeWarnings drains non-fatal resolver / codegen notices the
// kunai DSL pipeline attached to the probe (typically about chain-
// root conventions) onto stderr.
func printProbeWarnings(probe *program.Probe) {
	for _, w := range probe.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
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

// runCaptureLoop wires a loaded probe to the per-CPU sharded reader
// and pumps until SIGINT/SIGTERM. Every attach mode populates
// probe.InnerMaps after the R22 sharded-ringbuf hoist, so the
// sharded path is the only live path; captureLoopSharded owns the
// per-shard writer lifecycle.
//
// We still call output.NewWriter(basePath, isFexit) here to ensure
// the base path exists as a valid (SHB-only) pcap-ng file. Single-
// file consumers (`tcpdump -r out.pcap`) point at the base path; the
// per-CPU `.cpuN` companions hold the actual packets and are merged
// offline via `xdp-ninja convert`. Integration tests
// (run_pcap_test) rely on the base file's existence.
func runCaptureLoop(cmd *cli.Command, probe *program.Probe, isFexit bool, label string) error {
	defer func() {
		if cerr := probe.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing probe: %v\n", cerr)
		}
	}()
	if len(probe.InnerMaps) == 0 {
		return fmt.Errorf("probe has no inner ringbufs — sharded ringbuf hoist (R22) should populate them for every attach mode")
	}
	if err := captureLoopSharded(cmd, probe.InnerMaps, isFexit, label); err != nil {
		return err
	}

	// After capture, merge the per-CPU shard files into a single
	// time-ordered pcap-ng at the base path, so `-w out.pcap` yields one
	// ready-to-use file (the .cpuN shards are left in place). Only the
	// normal pcap path produces shard files; --raw-dump has its own
	// offline `convert`, --null-output writes nothing, and stdout is
	// already a single merged stream.
	basePath := cmd.String("write")
	if basePath != "" && !cmd.Bool("raw-dump") && !cmd.Bool("null-output") {
		// captureLoopSharded returns on Ctrl-C (or -c). Announce the
		// post-capture merge so the pause isn't mistaken for a hang.
		fmt.Fprintf(os.Stderr, "merging %d shard(s) into %s ...\n", len(probe.InnerMaps), basePath)
		if err := output.MergeShardFiles(basePath, len(probe.InnerMaps), isFexit); err != nil {
			fmt.Fprintf(os.Stderr, "warning: merging shards into %s: %v\n", basePath, err)
		} else {
			fmt.Fprintf(os.Stderr, "merged into %s (per-CPU .cpuN kept)\n", basePath)
		}
	}
	return nil
}

// captureLoopSharded: per-CPU shard goroutines, each writes to its
// own pcap file (no mutex). --null-output skips file writes for
// benchmarking; --raw-dump switches to the raw-bytes path.
func captureLoopSharded(cmd *cli.Command, inners []*ebpf.Map, isFexit bool, label string) error {
	basePath := cmd.String("write")
	null := cmd.Bool("null-output")
	rawDump := cmd.Bool("raw-dump")
	if rawDump {
		return captureLoopShardedRaw(cmd, inners, label, basePath)
	}

	// stdout (no -w) merges every shard into a single pcap-ng stream,
	// serialized by sharedMu so no per-core packets are dropped. With -w
	// each shard writes its own mutex-free .cpuN file (the high-throughput
	// path); merge offline with mergecap.
	stdoutMerge := basePath == "" && !null

	writers := make([]*output.Writer, len(inners))
	var sharedW *output.Writer
	var sharedMu sync.Mutex
	if !null {
		if stdoutMerge {
			w, err := output.NewWriter("", isFexit)
			if err != nil {
				return fmt.Errorf("opening stdout writer: %w", err)
			}
			sharedW = w
		} else {
			for i := range inners {
				w, err := output.NewWriter(fmt.Sprintf("%s.cpu%d", basePath, i), isFexit)
				if err != nil {
					return fmt.Errorf("opening per-CPU writer %d: %w", i, err)
				}
				writers[i] = w
			}
		}
	}
	defer func() {
		if sharedW != nil {
			_ = sharedW.Close()
		}
		for _, w := range writers {
			if w != nil {
				_ = w.Close()
			}
		}
	}()

	// Pick the write strategy once: null = drop, stdout = one writer
	// serialized by sharedMu, -w = mutex-free per-CPU writer. Keeps the
	// shared/per-CPU/null distinction out of the per-batch hot path.
	var writeShard func(shardIdx int, pkts []capture.Packet) error
	switch {
	case null:
		writeShard = func(int, []capture.Packet) error { return nil }
	case sharedW != nil:
		writeShard = func(_ int, pkts []capture.Packet) error {
			sharedMu.Lock()
			defer sharedMu.Unlock()
			return sharedW.WriteBatch(pkts)
		}
	default:
		writeShard = func(shardIdx int, pkts []capture.Packet) error {
			if writers[shardIdx] != nil {
				return writers[shardIdx].WriteBatch(pkts)
			}
			return nil
		}
	}

	fastReader := cmd.Bool("fast-reader")
	count := int64(cmd.Int("count"))
	var captured atomic.Int64
	var writeErrCount atomic.Int64
	var firstWriteErr atomic.Pointer[string]

	sink := func(shardIdx int, pkts []capture.Packet) error {
		if count > 0 && captured.Load() >= count {
			return nil
		}
		if err := writeShard(shardIdx, pkts); err != nil {
			writeErrCount.Add(1)
			if firstWriteErr.Load() == nil {
				msg := fmt.Sprintf("shard %d: %v", shardIdx, err)
				firstWriteErr.CompareAndSwap(nil, &msg)
			}
		}
		captured.Add(int64(len(pkts)))
		return nil
	}

	var stop func()
	readerLabel := "ringbuf.Reader"
	if fastReader {
		fr, err := capture.NewFastShardedReader(inners)
		if err != nil {
			return err
		}
		stop, err = fr.RunShardsFast(sink)
		if err != nil {
			return err
		}
		readerLabel = "fastrb (mmap bypass)"
	} else {
		r, err := capture.NewShardedReader(inners)
		if err != nil {
			return err
		}
		stop, err = r.RunShards(sink)
		if err != nil {
			return err
		}
	}

	mode := "sharded"
	if null {
		mode = "sharded null-output"
	}
	fmt.Fprintf(os.Stderr, "capturing (%s, %s, %d shards via %s)...\n", label, mode, len(inners), readerLabel)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	if count > 0 {
		for {
			select {
			case <-sig:
				stop()
				goto done
			default:
				if captured.Load() >= count {
					stop()
					goto done
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	} else {
		<-sig
		stop()
	}

done:
	fmt.Fprintf(os.Stderr, "\n%d packets captured\n", captured.Load())
	if n := writeErrCount.Load(); n > 0 {
		first := "?"
		if p := firstWriteErr.Load(); p != nil {
			first = *p
		}
		fmt.Fprintf(os.Stderr, "warning: %d WriteBatch errors; first: %s\n", n, first)
	}
	return nil
}

// captureLoopShardedRaw is the --raw-dump variant: per-CPU goroutines
// splat ringbuf record bytes verbatim into
// <basePath>.W<wall_offset_ns>.cpu<N>.raw files; offline conversion
// happens via the convert subcommand.
func captureLoopShardedRaw(cmd *cli.Command, inners []*ebpf.Map, label, basePath string) error {
	if basePath == "" {
		return fmt.Errorf("--raw-dump requires -w <path> (per-CPU files are not streamable to stdout)")
	}

	offset := capture.WallOffsetNs
	inMemMiB := cmd.Int("in-memory-buffer")
	writers := make([]output.Sink, len(inners))
	// Parallelise writer init: each in-memory writer mmaps and
	// MAP_POPULATE-prefaults its buffer (page-allocation blocks for
	// the full buffer size), so sequential init across all shards
	// would visibly delay capture start.
	var initWg sync.WaitGroup
	initErrs := make([]error, len(inners))
	for i := range inners {
		initWg.Add(1)
		go func(i int) {
			defer initWg.Done()
			path := fmt.Sprintf("%s.W%d.cpu%d.raw", basePath, offset, i)
			var w output.Sink
			var err error
			if inMemMiB > 0 {
				w, err = output.NewInMemoryRawDumpWriter(path, offset, int(inMemMiB)*1024*1024)
			} else {
				w, err = output.NewRawDumpWriter(path, offset)
			}
			if err != nil {
				initErrs[i] = err
				return
			}
			writers[i] = w
		}(i)
	}
	initWg.Wait()
	for i, err := range initErrs {
		if err != nil {
			for _, prev := range writers {
				if prev != nil {
					_ = prev.Close()
				}
			}
			return fmt.Errorf("opening raw-dump writer %d: %w", i, err)
		}
	}
	defer func() {
		for _, w := range writers {
			if w != nil {
				_ = w.Close()
			}
		}
	}()

	fastReader := cmd.Bool("fast-reader")
	count := int64(cmd.Int("count"))
	// Per-shard local counter, padded to a full 64 B cacheline so
	// adjacent goroutines incrementing their own slot don't
	// ping-pong the line across cores at 10+ Mpps. The hot path is
	// shardCounts[shardIdx].n++; only one shard goroutine ever
	// writes its own slot, and the final reader runs after stop().
	type paddedCounter struct {
		n   int64
		_   [56]byte
	}
	shardCounts := make([]paddedCounter, len(inners))
	var captured atomic.Int64

	var rawSink capture.RawShardSink
	if count > 0 {
		rawSink = func(shardIdx int, raw []byte) error {
			if captured.Load() >= count {
				return nil
			}
			if err := writers[shardIdx].WriteRaw(raw); err != nil {
				return err
			}
			captured.Add(1)
			return nil
		}
	} else {
		rawSink = func(shardIdx int, raw []byte) error {
			shardCounts[shardIdx].n++
			return writers[shardIdx].WriteRaw(raw)
		}
	}

	var stop func()
	if fastReader {
		fr, err := capture.NewFastShardedReader(inners)
		if err != nil {
			return err
		}
		stop, err = fr.RunRawShardsFast(rawSink)
		if err != nil {
			return err
		}
	} else {
		r, err := capture.NewShardedReader(inners)
		if err != nil {
			return err
		}
		stop, err = r.RunRawShards(rawSink)
		if err != nil {
			return err
		}
	}

	readerLabel := "ringbuf.Reader"
	if fastReader {
		readerLabel = "fastrb (mmap bypass)"
	}
	fmt.Fprintf(os.Stderr, "capturing (%s, sharded raw-dump, %d shards via %s, wall_offset_ns=%d)...\n",
		label, len(inners), readerLabel, offset)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	if count > 0 {
		for {
			select {
			case <-sig:
				stop()
				goto done
			default:
				if captured.Load() >= count {
					stop()
					goto done
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	} else {
		<-sig
		stop()
	}

done:
	total := captured.Load()
	for i := range shardCounts {
		total += shardCounts[i].n
	}
	// Close writers eagerly so flushAll() runs before we print the
	// durability summary; the deferred Close becomes a no-op for
	// nil'd slots.
	var anomalies output.WriteAnomalies
	for i, w := range writers {
		if w == nil {
			continue
		}
		if cerr := w.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: shard %d close: %v\n", i, cerr)
		}
		if r, ok := w.(output.AnomalyReporter); ok {
			anomalies.Add(r.Anomalies())
		}
		writers[i] = nil
	}
	fmt.Fprintf(os.Stderr, "\n%d packets captured (raw-dump)\n", total)
	if anomalies.Any() {
		fmt.Fprintf(os.Stderr,
			"warning: write-path anomalies: flush_errors=%d short_writes=%d bytes_lost=%d (%.1f MiB)\n",
			anomalies.FlushErrors, anomalies.ShortWrites, anomalies.BytesLost,
			float64(anomalies.BytesLost)/1024.0/1024.0)
	}
	if capture.LatencySamplePeriod > 0 {
		reportLatencySamples(cmd.String("latency-sample-output"))
	}
	return nil
}

// reportLatencySamples drains capture.LatencySamples (filled by the
// fast-reader's per-shard goroutines) into either a tsv file or a
// stderr percentile summary. Empty path = stderr summary; non-empty
// path = one int64 ns per line, all shards concatenated.
func reportLatencySamples(outputPath string) {
	var all []int64
	for _, shard := range capture.LatencySamples {
		all = append(all, shard...)
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "latency-sample: no samples collected")
		return
	}
	slices.Sort(all)
	pct := func(p float64) int64 {
		idx := int(float64(len(all)-1) * p)
		return all[idx]
	}
	fmt.Fprintf(os.Stderr,
		"latency-sample n=%d (ns): p50=%d p90=%d p99=%d p99.9=%d p99.99=%d max=%d\n",
		len(all), pct(0.50), pct(0.90), pct(0.99), pct(0.999), pct(0.9999), all[len(all)-1])
	if outputPath == "" {
		return
	}
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latency-sample: cannot write %s: %v\n", outputPath, err)
		return
	}
	defer func() { _ = f.Close() }()
	bw := bufio.NewWriter(f)
	for _, v := range all {
		_, _ = fmt.Fprintln(bw, v)
	}
	_ = bw.Flush()
	fmt.Fprintf(os.Stderr, "latency-sample: %d samples → %s\n", len(all), outputPath)
}

// runXDPNative handles --mode xdp: xdp-ninja is itself the XDP
// program on the netdev (no fentry/fexit piggybacking).
func runXDPNative(cmd *cli.Command) error {
	if err := validateXDPNativeFlags(cmd); err != nil {
		return err
	}

	if cmd.Bool("bench-drop") {
		program.XDPNativeBenchDrop = true
		fmt.Fprintln(os.Stderr, "warning: --bench-drop active: returning XDP_DROP after capture (bench-only)")
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
	printProbeWarnings(probe)
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


// formatKeyRanges renders a sorted key list compactly, collapsing runs of
// consecutive keys: [0,1,2,3] -> "0-3", [0,1,3,4,5] -> "0-1,3-5".
func formatKeyRanges(keys []uint32) string {
	if len(keys) == 0 {
		return ""
	}
	rng := func(a, b uint32) string {
		if a == b {
			return fmt.Sprintf("%d", a)
		}
		return fmt.Sprintf("%d-%d", a, b)
	}
	var parts []string
	start, prev := keys[0], keys[0]
	for _, k := range keys[1:] {
		if k == prev+1 {
			prev = k
			continue
		}
		parts = append(parts, rng(start, prev))
		start, prev = k, k
	}
	parts = append(parts, rng(start, prev))
	return strings.Join(parts, ",")
}

func logVerbose(cmd *cli.Command, format string, args ...any) {
	if cmd.Bool("verbose") {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

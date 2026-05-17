// xdp-ninja convert: offline converter for the --raw-dump output.
// Reads `*.W<offset>.cpu<N>.raw` files and emits a single pcap-ng via
// FastNgWriter. Records are streamed in per-file order; the BPF
// kernel timestamps make each per-CPU file strictly monotonic, and
// Wireshark / tshark re-sort across files on display.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/takehaya/xdp-ninja/internal/capture"
	"github.com/takehaya/xdp-ninja/internal/output"
)

var convertFlags = []cli.Flag{
	&cli.StringSliceFlag{
		Name: "read", Aliases: []string{"r"},
		Usage: "input raw-dump file(s) or glob pattern(s) (e.g. 'out.W*.cpu*.raw')",
	},
	&cli.StringFlag{
		Name: "output", Aliases: []string{"o"},
		Usage: "output pcap-ng file path (default stdout)",
	},
}

var convertCommand = &cli.Command{
	Name:  "convert",
	Usage: "convert raw-dump files to standard pcap-ng",
	Description: `Convert one or more --raw-dump output files into a standard
pcap-ng file that tcpdump / Wireshark / tshark can read directly.

Examples:
  xdp-ninja convert -r 'session.W*.cpu*.raw' -o session.pcapng
  xdp-ninja convert -r in.cpu0.raw -r in.cpu1.raw -o out.pcapng
  xdp-ninja convert -r 'session.W*.cpu*.raw'   # to stdout`,
	Flags:  convertFlags,
	Action: runConvert,
}

func runConvert(ctx context.Context, cmd *cli.Command) error {
	patterns := cmd.StringSlice("read")
	if len(patterns) == 0 {
		return fmt.Errorf("--read/-r required")
	}
	outputPath := cmd.String("output")

	var files []string
	seen := map[string]bool{}
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			return fmt.Errorf("glob %q: %w", p, err)
		}
		if len(matches) == 0 {
			matches = []string{p}
		}
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			files = append(files, m)
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("no input files matched")
	}

	var sink io.Writer
	var sinkCloser io.Closer
	if outputPath == "" {
		sink = os.Stdout
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output: %w", err)
		}
		sink = f
		sinkCloser = f
	}
	if sinkCloser != nil {
		defer func() { _ = sinkCloser.Close() }()
	}
	bw := bufio.NewWriterSize(sink, 1<<20)
	defer func() { _ = bw.Flush() }()

	fastW, err := output.NewFastNgWriter(bw)
	if err != nil {
		return fmt.Errorf("creating pcap-ng writer: %w", err)
	}

	totalRecords := 0
	for _, path := range files {
		n, err := convertFile(path, fastW)
		if err != nil {
			return fmt.Errorf("converting %s: %w", path, err)
		}
		totalRecords += n
	}
	dest := outputPath
	if dest == "" {
		dest = "stdout"
	}
	fmt.Fprintf(os.Stderr, "converted %d records from %d file(s) → %s\n",
		totalRecords, len(files), dest)
	return nil
}

// convertFile reads one raw-dump file and emits each record as an
// EPB via fastW. Returns the number of records emitted.
func convertFile(path string, fastW *output.FastNgWriter) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReaderSize(f, 1<<20)

	hdr := make([]byte, output.RawDumpHeaderSize)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return 0, fmt.Errorf("reading header: %w", err)
	}
	if !bytes.Equal(hdr[0:16], output.RawDumpMagic) {
		return 0, fmt.Errorf("magic mismatch: got %q, want %q", hdr[0:16], output.RawDumpMagic)
	}
	if binary.BigEndian.Uint32(hdr[16:20]) != output.RawDumpEndianMagic {
		return 0, fmt.Errorf("endian magic mismatch (file produced on a different-endian host?)")
	}
	wallOffsetNs := binary.LittleEndian.Uint64(hdr[20:28])

	meta := make([]byte, capture.MetadataSize)
	var data []byte
	count := 0
	for {
		if _, err := io.ReadFull(br, meta); err != nil {
			if err == io.EOF {
				break
			}
			return count, fmt.Errorf("reading record metadata: %w", err)
		}
		kernelTs := capture.RecordKernelTs(meta)
		caplen := capture.RecordCapLen(meta)
		if cap(data) < int(caplen) {
			data = make([]byte, caplen)
		} else {
			data = data[:caplen]
		}
		if caplen > 0 {
			if _, err := io.ReadFull(br, data); err != nil {
				return count, fmt.Errorf("reading record data: %w", err)
			}
		}
		ts := time.Unix(0, int64(kernelTs+wallOffsetNs))
		if err := fastW.WritePacket(ts, data); err != nil {
			return count, fmt.Errorf("writing EPB: %w", err)
		}
		count++
	}
	return count, nil
}

// observer attaches one example to the hooks of the walkthrough program.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

var hooks = []string{"ninja_recent_push", "ninja_recent_pop", "ninja_seen_peek"}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) != 4 || !slices.Contains([]string{"count", "conditional", "latency"}, os.Args[1]) {
		return fmt.Errorf("usage: %s count|conditional|latency OBJECT PROG_ID", os.Args[0])
	}
	kind := os.Args[1]
	id, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		return err
	}
	target, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return err
	}
	defer func() { _ = target.Close() }()
	spec, err := ebpf.LoadCollectionSpec(os.Args[2])
	if err != nil {
		return err
	}
	names, mapName, err := observerLayout(spec, kind)
	if err != nil {
		return err
	}
	for _, p := range spec.Programs {
		p.AttachTarget = target
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load observer: %w", err)
	}
	defer coll.Close()
	// observerLayout puts the latency entry observer first, before either push.
	for _, name := range names {
		p, ok := coll.Programs[name]
		if !ok {
			return fmt.Errorf("%s object lacks program %q", kind, name)
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			return err
		}
		defer func() { _ = l.Close() }()
	}
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("%s object lacks map %q", kind, mapName)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("attached %s\n", kind)
	if kind == "count" {
		return printCounters(ctx, m)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		b := rec.RawSample
		switch kind {
		case "conditional":
			if len(b) != 32 {
				return fmt.Errorf("conditional event size: %d", len(b))
			}
			op := binary.LittleEndian.Uint32(b)
			if int(op) >= len(hooks) {
				return fmt.Errorf("unknown op: %d", op)
			}
			fmt.Printf("hook=%s site=%d value=%d ret=%d cpu=%d\n", hooks[op], binary.LittleEndian.Uint32(b[4:]),
				binary.LittleEndian.Uint64(b[8:]), int32(binary.LittleEndian.Uint64(b[16:])), binary.LittleEndian.Uint32(b[24:]))
		case "latency":
			if len(b) != 24 {
				return fmt.Errorf("latency event size: %d", len(b))
			}
			fmt.Printf("site=%d ret=%d ns=%d\n", binary.LittleEndian.Uint32(b),
				int32(binary.LittleEndian.Uint64(b[8:])), binary.LittleEndian.Uint64(b[16:]))
		}
	}
}

// Return programs in attachment order and the map read by user space.
func observerLayout(spec *ebpf.CollectionSpec, kind string) ([]string, string, error) {
	names := []string{"on_push", "on_pop", "on_peek"}
	mapName, mapType := "events", ebpf.RingBuf
	switch kind {
	case "count":
		mapName, mapType = "counters", ebpf.PerCPUHash
	case "conditional":
	case "latency":
		// Entry must be attached before either consumer of its timestamp.
		names = []string{"on_entry", "on_push", "on_seen_push"}
	default:
		return nil, "", fmt.Errorf("unknown observer kind %q", kind)
	}
	if len(spec.Programs) != len(names) {
		return nil, "", fmt.Errorf("%s object: expected %d programs, got %d", kind, len(names), len(spec.Programs))
	}
	for _, name := range names {
		if p, ok := spec.Programs[name]; !ok || p == nil {
			return nil, "", fmt.Errorf("%s object lacks program %q", kind, name)
		}
	}
	if m, ok := spec.Maps[mapName]; !ok || m == nil || m.Type != mapType {
		return nil, "", fmt.Errorf("%s object requires %s map %q", kind, mapType, mapName)
	}
	return names, mapName, nil
}

type counterKey struct{ Op, Site uint32 }
type counter struct{ Calls, Failures uint64 }

func printCounters(ctx context.Context, m *ebpf.Map) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			totals := make(map[counterKey]counter)
			var key counterKey
			var values []counter
			it := m.Iterate()
			for it.Next(&key, &values) {
				var sum counter
				for _, c := range values {
					sum.Calls += c.Calls
					sum.Failures += c.Failures
				}
				totals[key] = sum
			}
			if err := it.Err(); err != nil {
				return err
			}
			keys := make([]counterKey, 0, len(totals))
			for key := range totals {
				keys = append(keys, key)
			}
			slices.SortFunc(keys, func(a, b counterKey) int {
				if a.Op != b.Op {
					return int(a.Op) - int(b.Op)
				}
				return int(a.Site) - int(b.Site)
			})
			fmt.Println("snapshot")
			for _, key := range keys {
				if int(key.Op) >= len(hooks) {
					return fmt.Errorf("unknown op: %d", key.Op)
				}
				c := totals[key]
				fmt.Printf("hook=%s site=%d calls=%d failures=%d\n", hooks[key.Op], key.Site, c.Calls, c.Failures)
			}
		}
	}
}

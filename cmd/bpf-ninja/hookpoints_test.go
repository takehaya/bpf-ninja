package main

import (
	"context"
	"strings"
	"testing"
)

func TestHookPcapngFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--hook-pcapng"},
		{"--hook-pcapng", "--func", "a", "--mode", "exit"},
		{"--hook-pcapng", "--func", "a", "--mode", "xdp"},
		{"--hook-pcapng", "--func", "a", "--raw-dump"},
		{"--hook-pcapng", "--func", "a", "--arg-echo"},
		{"--hook-pcapng", "--func", "a", "--dump-asm", "all"},
	} {
		err := newRootCommand().Run(context.Background(), append([]string{"bpf-ninja"}, args...))
		if err == nil || !strings.Contains(err.Error(), "--hook-pcapng requires") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestHookStartParsing(t *testing.T) {
	for _, values := range [][]string{{""}, {"a="}, {"=eth"}, {"@entry=eth"}, {"a=eth", " a =ipv4"}} {
		if _, e := parseHookStarts(values); e == nil {
			t.Fatalf("accepted %v", values)
		}
	}
	starts, e := parseHookStarts([]string{"b=eth/ipv4[ttl==64]", "a=eth"})
	if e != nil || starts["b"] != "eth/ipv4[ttl==64]" {
		t.Fatal(starts, e)
	}
	got := appendHookStarts([]string{"z", "b"}, starts)
	if strings.Join(got, ",") != "z,b,a" {
		t.Fatal(got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--start", "a=eth", "-p", "1"}, "require --hook-pcapng"},
		{[]string{"--run-tracking", "ctx", "-p", "1"}, "require --hook-pcapng"},
		{[]string{"--hook-pcapng", "--start", "a=", "-p", "1"}, "NAME=FILTER"},
		{[]string{"--hook-pcapng", "--func", "a", "--run-tracking", "bogus", "-p", "1"}, "--run-tracking must be auto, percpu or ctx"},
	} {
		err := newRootCommand().Run(context.Background(), append([]string{"bpf-ninja"}, tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v, want %s", tc.args, err, tc.want)
		}
	}
}

# Inject hook observers

Four small fentry observers for the unmodified program and loader in [inject-walkthrough](../inject-walkthrough).
The [guide](../../docs/en/inject-observers.md) explains the examples and shows recorded VM output.

- `bpf/count.c`: count calls and failures per hook/site in an observer-owned per-CPU map; print cumulative totals every second.
- `bpf/conditional.c`: send only failed calls to a ring buffer, including the CPU ID.
- `bpf/packet.c`: read the packet length and first eight bytes through the hook's XDP context.
- `bpf/latency.c`: record entry time per CPU and report elapsed nanoseconds at each queue or bloom-filter push.
- `observer/`: one Go command to attach and read any of the four examples.

## Build

From the repository root, with Go, `/usr/bin/clang`, libbpf headers and libpcap development files installed:

```sh
go build -o bpf-ninja ./cmd/bpf-ninja
./examples/inject-observers/build.sh
```

The script builds the four BPF objects and one observer binary in `build/`, and builds the walkthrough's program and loader there without copying their sources.
`go vet ./...` includes the observer command.

## Run one example

In a root shell inside a test VM, from this directory:

```sh
name=count # or conditional, packet, latency
rules=../inject-walkthrough/rules.json
if [ "$name" = latency ]; then rules=latency-rules.json; fi
../../bpf-ninja inject-run --config "$rules" --hooks-json build/hooks.json \
  -- ./build/loader-bin build/prog.o > build/id.txt 2> build/loader.log &
launcher=$!
for i in $(seq 90); do
  [ -s build/id.txt ] && break
  kill -0 "$launcher" || break
  sleep 1
done
./build/observer-bin "$name" "build/$name.o" "$(cat build/id.txt)"
```

Interrupt the observer with Ctrl-C when finished.
The loader exits after one minute; `kill -INT "$launcher"` stops it sooner.
Start a fresh loader for each example.
Nothing is attached to an interface; the loader uses `BPF_PROG_TEST_RUN` on zero-filled packets of 64, 80, 96 and 112 bytes.

## Verify in a VM

`verify.sh` starts a fresh loader for each example, waits up to 90 seconds for its program ID, then runs its observer for seven seconds.
It checks for counters, failed pushes with a CPU ID, packet lengths and bytes, positive elapsed times, and `XDP_PASS` from every recorded loader run.
A timeout status of 124 ends each observation window as intended.
Logs and hook metadata stay in `build/$(uname -r)/`.

From the repository root on a host with vimto installed:

```sh
VIMTO_DISABLE_KVM=1 flock /tmp/bpf-ninja-observers-vm.lock \
  vimto -sudo -kernel ghcr.io/cilium/ci-kernels:7.0 -memory 2G -smp cpus=2 \
  exec -- "$PWD/examples/inject-observers/verify.sh"
```

Repeat with `:6.1`.
Use an absolute script path: this vimto version could not mount the relative script directory.

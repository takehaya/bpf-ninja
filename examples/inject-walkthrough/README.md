# inject-walkthrough

The sources of [docs/en/inject-walkthrough.md](../../docs/en/inject-walkthrough.md): the XDP program, its loader, the fentry observer and the rule.

- `bpf/prog.c`: the program whose queue and bloom filter calls are observed.
- `loader/`: loads `prog.o`, prints its program ID and runs it once a second with `BPF_PROG_TEST_RUN`.
- `bpf/observer.c` and `observer/`: attach to the hooks of a transformed program and print each call.
- `rules.json`: the rule for `inject-run`.

Build them from this directory:

```sh
clang -O2 -g -target bpf -c bpf/prog.c -o prog.o
clang -O2 -g -target bpf -c bpf/observer.c -o observer.o
go build -o loader-bin ./loader
go build -o observer-bin ./observer
```

Then, as root, load the program with the hooks and attach the observer to the program ID the loader prints, which is also the `prog_id` in `hooks.json`:

```sh
bpf-ninja inject-run --config rules.json --hooks-json hooks.json -- ./loader-bin prog.o > id.txt &
sleep 1
./observer-bin observer.o "$(cat id.txt)"
```

The loader exits after a minute.
Nothing is attached to an interface.

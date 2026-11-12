# Follow-across-reload scenario

A loader runs under `inject-run`, sends numbered packets through an XDP
program with `BPF_PROG_TEST_RUN`, and replaces the program while they flow.
A capture started at the first generation's `ninja_policies` hook has to deal
with the second generation. The scenario never attaches to an interface.

Build static binaries and BPF objects on the development host:

```sh
scripts/test/follow/build.sh /tmp/follow-vm
```

Copy that directory into a disposable x86-64 VM and run `./run.sh` as root.
The build host needs clang with BPF support and Linux/libbpf headers.
Runtime needs `python3`, `unshare` and `pkill`.
`scripts/test/privileged.py` builds and runs the scenario after its Go suites,
on the host and in each matrix kernel's VM.
When `run.sh` is invoked directly, diagnostics and pcaps remain in a unique
`follow-results.*` directory inside the copied directory.
`scripts/test/privileged.py` prints the failing case's `inject.err` and capture
stderr before deleting its temporary build directory and all results.

The loader starts loading generation 2 after packet 99 on another goroutine and
keeps sending on generation 1 until the load returns; it then switches, closes
generation 1, and sends 300 packets on generation 2. The sequence number is the
packet's IPv4 ID, and
`check.py` reads it back from the pcap with the independent reader in
`scripts/test/assert_pcap.py`.

| Case | Generation 2 | Capture | Checked |
|---|---|---|---|
| `held` | same program | `--arg-filter 'value->port!=0'` | all packets are in the pcap, each once, on one interface; no `FOLLOW GAP`; status `complete`; `follow_attached=1 follow_held=1 follow_gaps=0`; `inject-run` logs that it held the load for the capture |
| `polling` | same program | in its own network namespace, `--arg-filter 'value->port!=0'` | every generation 1 packet and the last packet are in the pcap, on one interface, none twice; one `FOLLOW GAP reason=late` for generation 2; status `incomplete`; `follow_attached=1 follow_gaps=1` |
| `unresolved` | `struct pol` without `port` | `--arg-filter 'value->port!=0'` | exactly the generation 1 packets are in the pcap; one `FOLLOW GAP reason=filter_unresolved`; status `incomplete`; `follow_attached=0 follow_gaps=1` |
| `contended` | same program | two captures of the same hook | generation 2 has exactly one tracing link; one capture has `follow_attached=1 follow_held=1 follow_gaps=0` and status `complete`; the other reports one `FOLLOW GAP reason=observed_by_other`, has `follow_attached=0 follow_held=0 follow_gaps=1`, and ends `incomplete` |

In the `held` case the capture is subscribed to `inject-run`, which keeps the
loader's load stopped until the capture has attached to generation 2, while
the loader's other thread keeps sending on generation 1.
In the `polling` case the capture cannot reach `inject-run`'s socket and
finds generation 2 by polling program IDs, so the packets generation 2 handled before the observer was attached may be
missing; the case requires that the capture reports this rather than that
nothing is missing.

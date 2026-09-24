# Integration tests

Run `make test-integration` with root access, clang with BPF support, iproute2,
ping, bpftool, and tcpdump installed. The suite creates the `xdptest`,
`xdptctest`, and `xdpargtest` namespaces and their test interfaces. Run one suite
at a time and do not reuse those names for other work.

`capture_helpers.sh` waits for the CLI's `capturing (...)...` reader-ready line
before sending test traffic. A successful capture requires exit status 0 and
exactly one `N packets captured` shutdown summary. Negative tests signal the
actual capture process after sending traffic; a missing summary, timeout,
premature exit, or signal termination without graceful shutdown is a failure.
Diagnostics are printed on failure. An explicit return status of 77 denotes an
optional capability skip; diagnostic text alone cannot turn a failure into a
skip. Final-file content checks are separate from these lifecycle checks.

Run the helper fault-injection tests without root or network setup:

```sh
python3 -m unittest discover -s scripts/tests -p test_capture_helpers.py -v
go test ./internal/testutil
```

The Go compiler helper skips only a missing clang in local runs. With `CI=true`
or `CI=1`, missing clang fails too. An installed compiler returning an error
always fails the test, including invalid C or missing BPF target support.

`BINARY` can select another executable for the shell suite. The helper tests
use `CAPTURE_READY_POLLS`, `CAPTURE_TIMEOUT` (seconds), and `CAPTURE_SETTLE`
(seconds) to exercise startup and timeout failures quickly.

#!/usr/bin/env python3
"""Run and audit the privileged suites used by both make and CI."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = "github.com/takehaya/bpf-ninja/internal/program"
INJECT = "github.com/takehaya/bpf-ninja/pkg/inject"
SYSCALLHOOK = "github.com/takehaya/bpf-ninja/pkg/syscallhook"


def allowed_skip(package, test, output, kernel):
    if package == INJECT:
        # The native control shape falls through on kernels that lose tail-call
        # reachability; the guarded refusal test covers those kernels instead.
        if test == "TestBpfTailCallInSubprogram":
            return "kernel loses tail-call reachability" in output
        # The opt-in census requires external corpus inputs on every kernel.
        if test == "TestTranslationValidationCensus":
            return "set BPF_NINJA_VALIDATE_OBJECTS, BPF_NINJA_VALIDATE_CENSUS and BPF_NINJA_VALIDATE_OUTPUT" in output
        if test == "TestBpfLookupHooksNetfilter":
            return kernel == "6.1" and "BPF_PROG_TYPE_NETFILTER not supported" in output
        # 7.3 rejects a tail call reachable from a bpf_loop callback outright.
        if test in {"TestBpfStackLimitsAcrossCalls/callback", "TestBpfStackLimitsAcrossCalls/callback-global"}:
            return kernel == "7.3-rc4" and "kernel forbids tail calls in callbacks" in output
        # 7.3 forbids updating a socket map from tc, so the fixture itself fails.
        if kernel == "7.3-rc4" and test in {"TestBpfSockHashUpdateTC", "TestBpfSockHashUpdateTCStatic"}:
            return "kernel forbids sockmap updates from tc" in output
        # BPF_PROG_TEST_RUN sets cgroup_skb packet pointers from 6.15 on.
        if test in {"TestBpfDispatchCGroupSKBStatic", "TestBpfLookupHooksCGroupSKB"}:
            return kernel in {"6.1", "6.6", "6.12"} and "sets no cgroup_skb packet pointers" in output
        # The lookup wrapper's frame fits only under the 16-byte frame rule of
        # 6.9 and later JIT kernels.
        if test in {
            "TestBpfLookupWrapper/hit", "TestBpfLookupWrapper/miss", "TestBpfLookupWrapper/any",
            "TestBpfLookupWrapperGeneric/static=true", "TestBpfLookupWrapperNoSpillInSubprogram",
        }:
            return kernel in {"6.1", "6.6"} and "kernel uses 32-byte frame rounding" in output
        # Hooks for read-only and runtime-resolved maps and the dispatch hook
        # tag their parameters arg:untrusted, which 6.15 and older reject.
        # GenericKinds skips per map-kind subtest, so match the base test name.
        return kernel in {"6.1", "6.6", "6.12", "6.15"} and test.split("/", 1)[0] in {
            "TestBpfLookupInjectionReadOnlyMap", "TestBpfLookupInjectionMapInMap",
            "TestBpfLookupInjectionGenericKinds", "TestBpfLookupInjectionDevMap", "TestBpfDispatch", "TestBpfDispatchTC",
            "TestBpfDispatchMiss", "TestBpfDispatchAny", "TestBpfDispatchAnyTC", "TestBpfDispatchCGroupSKB",
            "TestBpfMapCallsDispatch", "TestBpfMapCallsInnerUpdate",
            "TestBpfSpecialFieldsLookup", "TestBpfSockHashUpdateTC", "TestBpfQueueOpsDispatch",
            "TestBpfQueueOpsInner", "TestBpfReadOnlyArg", "TestBpfReadOnlyArgShapes", "TestBpfReadOnlyArgCalls",
            "TestBpfReadOnlyKconfigArg", "TestBpfLookupWrapperGeneric",
        } and "kernel lacks arg:untrusted" in output
    # The record tests at untrusted and non-static dispatch hooks need
    # arg:untrusted, which 6.15 and older reject; the static dispatch case
    # (TestBpfRecordDispatchStatic) must pass on every kernel.
    if package == PROGRAM and kernel in {"6.1", "6.6", "6.12", "6.15"} and test in {
        "TestBpfRecordUntrustedHook", "TestBpfRecordDispatchHook",
    }:
        return "kernel lacks arg:untrusted" in output
    if package != PROGRAM:
        return False
    unsupported_tc = {
        "TestBpfFilterSetTC/F4", "TestBpfFilterSetTC/F5",
        "TestBpfFilterCorpusTC/D04", "TestBpfFilterCorpusTC/E00",
        "TestBpfFilterCorpusTC/E03",
    }
    if test in unsupported_tc:
        return "rejected at compile time" in output or "rejects it at compile time" in output
    if kernel and test == "TestBpfTailcallSubfunc":
        return "veth not supported on this kernel" in output
    if kernel and test in {"TestBpfVlanWireFrameAtTC", "TestBpfVlanWireFrameAtTCEdges", "TestBpfVlanWireFrameAtTCEgress"}:
        return "veth unavailable" in output or "neither tcx nor clsact" in output or "vlan device unavailable" in output
    if kernel == "6.1" and test.startswith(("TestBpfGatedReentry/", "TestBpfExtensionReentry/")):
        return "neither tcx nor clsact" in output
    if kernel == "6.1" and test in {
        "TestBpfEntryWithDSLFilterNetfilter", "TestBpfExitWithDSLFilterNetfilter",
        "TestBpfFexitReturnLayoutNetfilter", "TestBpfMultiPointLoad/netfilter-entry",
        "TestBpfOrigLen/netfilter-fentry", "TestBpfStaticNetfilterInjectedHook",
        "TestBpfStaticNetfilterGatedIdentity", "TestBpfStaticNetfilterContextReadFailure",
        "TestBpfStaticNetfilterGatedContextReadFailure",
    }:
        return "BPF_PROG_TYPE_NETFILTER not supported" in output
    return False


def audit(events, expected, kernel):
    outcomes, output, packages = {}, {}, set()
    failures = []
    for event in events:
        package, test = event.get("Package"), event.get("Test")
        key = (package, test)
        if event.get("Output"):
            output[key] = output.get(key, "") + event["Output"]
        action = event.get("Action")
        if action in {"pass", "skip", "fail"}:
            if test:
                outcomes[key] = action
            elif action == "pass":
                packages.add(package)
            else:
                failures.append(f"package {package}: {action}")
    for key, action in outcomes.items():
        if action == "fail":
            failures.append(f"{key}: failed")
        elif action == "skip" and not allowed_skip(*key, output.get(key, ""), kernel):
            failures.append(f"{key}: unexpected skip: {output.get(key, '').strip()}")
    for key in expected:
        if key not in outcomes:
            failures.append(f"{key}: required test did not finish")
        if key[0] not in packages:
            failures.append(f"{key[0]}: package did not pass")
    return sorted(set(failures))


# The supervisor tests that need root: the integration loaders and the
# syscall-stop modes, including the fallback from the seccomp filter.
SYSCALLHOOK_TESTS = (
    "TestIntegrationMapTypes", "TestIntegrationLoader", "TestIntegrationIndirectJump", "TestIntegrationJumpLimit",
    "TestIntegrationInjectHold",
    "TestBpfAutoStatic", "TestBPFStopsBehaviour", "TestBPFStopsCount", "TestBPFStopsDefault", "TestBPFStopsFallback",
    "TestBPFStopsOutlivingChild", "TestBPFStopsLeaderExit", "TestBPFStopsCancelEndsChild",
    "TestBPFStopsChildNotInstrumented", "TestBPFStopsTargetListener", "TestBPFStopsCommonAttrs",
    "TestBPFStopsDaemonizingTarget", "TestBPFStopsForeignExecDropsFormerTID", "TestBPFStopsChildPidfdFailure",
    "TestBPFStopsMultipleNewbornRegistrationFailure",
)


def syscallhook_suite(binary, log_path):
    # Run the same tagged binary in CI and in VMs without a Go toolchain.
    command = [str(Path(binary).resolve()), "-test.v", "-test.count=1", "-test.timeout=5m",
               "-test.run=^(" + "|".join(SYSCALLHOOK_TESTS) + ")$"]
    passes = [
        ("default", [], SYSCALLHOOK_TESTS, dict(os.environ)),
        ("every-syscall", ["-test.skip", "^TestBPFStops"],
         tuple(name for name in SYSCALLHOOK_TESTS if not name.startswith("TestBPFStops")),
         dict(os.environ, SYSCALLHOOK_TEST_EVERY_SYSCALL="1")),
    ]
    # A test that runs this binary again as a loader may echo the loader's
    # results; while a top-level test runs, only its own results count.
    with open(log_path, "w", encoding="utf-8") as log:
        for name, extra, tests, env in passes:
            events = []
            running = None
            pass_command = command + extra
            print("+ " + " ".join(pass_command), flush=True)
            with subprocess.Popen(pass_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, env=env) as process:
                for line in process.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                    started = re.match(r"=== RUN\s+([^/\s]+)$", line)
                    if started and running is None:
                        running = started[1]
                    match = re.match(r"\s*--- (PASS|FAIL|SKIP): (\S+)", line)
                    if match and running in (None, match[2].split("/", 1)[0]):
                        events.append({"Package": SYSCALLHOOK, "Test": match[2], "Action": match[1].lower()})
                        if match[2] == running:
                            running = None
                events.append({"Package": SYSCALLHOOK, "Action": "pass" if process.wait() == 0 else "fail"})
            expected = {(SYSCALLHOOK, test) for test in tests}
            failures = audit(events, expected, None)
            for failure in failures:
                print(f"AUDIT FAIL ({name}): {failure}", file=sys.stderr)
            if failures:
                return 1
    print("Privileged supervisor audit passed in default and every-syscall modes: all required tests passed; no skips.")
    return 0


def follow_scenario(kernel):
    """Replace a program under a running capture (scripts/test/follow).

    The scenario is a shell script around inject-run, a loader and the
    capture, so it runs after the Go suites: built here, then run as root on
    the host or in the kernel's VM.
    """
    with tempfile.TemporaryDirectory(prefix="bpf-ninja-follow-") as out:
        subprocess.run([str(ROOT / "scripts/test/follow/build.sh"), out], check=True)
        prefix = ["vimto", "-sudo", "-kernel", ":"+kernel, "-memory", "4G", "-smp", "cpus=2", "--"] if kernel else []
        command = prefix + ["sh", "-c", f"cd {shlex.quote(out)} && ./run.sh"]
        print("+ " + " ".join(command), flush=True)
        return subprocess.run(command).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", choices=["6.1", "6.6", "6.12", "6.15", "6.18", "7.0", "7.1", "7.2", "7.3-rc4"])
    parser.add_argument("--log", default="/tmp/bpf-ninja-privileged.jsonl")
    parser.add_argument("--syscallhook-binary", help="run a prebuilt -tags integration syscallhook test binary")
    args = parser.parse_args()
    if not args.kernel and os.geteuid() != 0:
        parser.error("host suites require root; use make test-bpf")
    if args.syscallhook_binary:
        if args.kernel:
            parser.error("run --syscallhook-binary inside the target VM, without --kernel")
        return syscallhook_suite(args.syscallhook_binary, args.log)
    os.chdir(ROOT)
    suites = [
        ("./internal/program", "^TestBpf" if args.kernel else "^Test"),
        ("./internal/attach", "^Test"),
        ("./internal/capture/...", "^Test"),
        ("./cmd/bpf-ninja", "^TestBpf" if args.kernel else "^Test"),
        ("./pkg/kunai/dsltest", "^Test"),
        ("./pkg/inject", "^TestBpf" if args.kernel else "^Test"),
        ("./pkg/injectcheck", "^TestBpf" if args.kernel else "^Test"),
    ]
    events, expected = [], set()
    env = dict(os.environ, CI="true", CGO_ENABLED="1")
    # Legacy filters are required here; use the same tag for listing and running.
    go_test = ["go", "test", "-tags", "enable_libpcap"]
    if args.kernel:
        # TestVerifierStats checks its per-kernel budgets only on the matrix
        # images; a host kernel's numbers are logged, never asserted.
        env["KUNAI_VERIFIER_STRICT"] = "1"
    with open(args.log, "w", encoding="utf-8") as log:
        for package, pattern in suites:
            # Enumerate selected tests independently of the execution report;
            # a successful command with no tests cannot satisfy the audit.
            listing = subprocess.run(
                go_test + ["-json", "-list", pattern, package],
                check=True, capture_output=True, text=True, env=env,
            )
            selected = set()
            for line in listing.stdout.splitlines():
                event = json.loads(line)
                name = event.get("Output", "").strip()
                if re.fullmatch(r"Test\w+", name):
                    selected.add((event["Package"], name))
            if not selected:
                raise RuntimeError(f"no tests selected in {package}")
            expected.update(selected)
            prefix = ["vimto", "-sudo", "-kernel", ":"+args.kernel,
                      "-memory", "4G", "-smp", "cpus=2", "--"] if args.kernel else []
            # dsltest loads ~17k programs, and kernel 7.0+ verifies the TCP
            # option filters among them several times slower than 6.x did.
            command = prefix + go_test + ["-json", "-count=1", "-timeout=15m", "-run", pattern, package]
            print("+ " + " ".join(command), flush=True)
            with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, env=env) as process:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        print(line, end="", flush=True)
                        continue
                    events.append(event)
                    if event.get("Output"):
                        print(event["Output"], end="", flush=True)
                if process.wait() != 0:
                    print(f"suite command failed: {package}", file=sys.stderr)
                    return 1
    failures = audit(events, expected, args.kernel)
    for failure in failures:
        print(f"AUDIT FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"Privileged audit passed: {len(expected)} required top-level tests; no unexpected skips.")
    if follow_scenario(args.kernel) != 0:
        print("follow scenario failed", file=sys.stderr)
        return 1
    print("Follow scenario passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

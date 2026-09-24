#!/usr/bin/env python3
"""Run and audit the privileged suites used by both make and CI."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = "github.com/takehaya/bpf-ninja/internal/program"


def allowed_skip(package, test, output, kernel):
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
    if kernel == "6.1" and test in {
        "TestBpfEntryWithDSLFilterNetfilter", "TestBpfExitWithDSLFilterNetfilter",
        "TestBpfFexitReturnLayoutNetfilter"
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", choices=["6.1", "6.6", "6.12", "6.15", "6.18", "7.0"])
    parser.add_argument("--log", default="/tmp/bpf-ninja-privileged.jsonl")
    args = parser.parse_args()
    if not args.kernel and os.geteuid() != 0:
        parser.error("host suites require root; use make test-bpf")
    os.chdir(ROOT)
    suites = [
        ("./internal/program", "^TestBpf" if args.kernel else "^Test"),
        ("./internal/attach", "^Test"),
        ("./internal/capture/...", "^Test"),
        ("./cmd/bpf-ninja", "^TestBpf" if args.kernel else "^Test"),
        ("./pkg/kunai/dsltest", "^Test"),
    ]
    events, expected = [], set()
    env = dict(os.environ, CI="true")
    with open(args.log, "w", encoding="utf-8") as log:
        for package, pattern in suites:
            # Enumerate selected tests independently of the execution report;
            # a successful command with no tests cannot satisfy the audit.
            listing = subprocess.run(
                ["go", "test", "-json", "-list", pattern, package],
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
            prefix = ["vimto", "-sudo", "-kernel", ":"+args.kernel, "--"] if args.kernel else []
            command = prefix + ["go", "test", "-json", "-count=1", "-timeout=5m", "-run", pattern, package]
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
    return 0


if __name__ == "__main__":
    sys.exit(main())

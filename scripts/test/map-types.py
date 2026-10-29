#!/usr/bin/env python3
"""Root-only CLI integration check. Inputs: ninja, loader, ELF, fresh output dir, legacy ELF."""
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

if not __debug__:
    raise SystemExit("map-types.py requires Python without -O or PYTHONOPTIMIZE")

if len(sys.argv) != 6:
    raise SystemExit("usage: map-types.py NINJA LOADER ELF OUTPUT_DIR LEGACY_ELF")
if os.geteuid() != 0:
    raise SystemExit("requires root and BPF privileges")

ninja, loader, source_elf = map(lambda p: str(Path(p).resolve()), sys.argv[1:4])
legacy_elf = str(Path(sys.argv[5]).resolve())
out = Path(sys.argv[4]).resolve()
out.mkdir(parents=True, exist_ok=False)
commands = (out / "commands.jsonl").open("w")


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, directory, name, background=False):
    commands.write(json.dumps({"argv": argv, "directory": str(directory), "name": name}) + "\n")
    commands.flush()
    stdout = (directory / (name + ".stdout")).open("wb")
    stderr = (directory / (name + ".stderr")).open("wb")
    proc = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
    stdout.close()
    stderr.close()
    if background:
        return proc
    try:
        rc = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        (directory / (name + ".exit")).write_text(str(proc.returncode) + "\n")
        raise
    (directory / (name + ".exit")).write_text(str(rc) + "\n")
    return rc


def wait_for(predicate, proc):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early: {proc.args} status={proc.returncode}")
        time.sleep(0.05)
    raise RuntimeError(f"timeout: {proc.args}")


def packets(path):
    data = path.read_bytes()
    pos = 0
    result = []
    while pos < len(data):
        kind, size = struct.unpack_from("<II", data, pos)
        check(size >= 12 and pos + size <= len(data), "invalid pcapng block")
        check(struct.unpack_from("<I", data, pos + size - 4)[0] == size, "pcapng block trailer length mismatch")
        if kind == 6:
            caplen, origlen = struct.unpack_from("<II", data, pos + 20)
            check(caplen == origlen == 64, f"unexpected packet lengths: {caplen}/{origlen}")
            result.append(data[pos + 28:pos + 28 + caplen])
        pos += size
    return result


# No interface attachment or host setting changes; packets use BPF_PROG_TEST_RUN.
command(["uname", "-a"], out, "kernel")
for mode in ("without", "with", "named", "legacy", "legacy-missing", "existing-btf"):
    elf = legacy_elf if mode in ("legacy", "legacy-missing") else source_elf
    d = out / mode
    d.mkdir()
    rule = {"program": "ingress", "map": "sessions", "hook": "observe", "stack_lowest_offset": -4}
    if mode != "without":
        rule["map_btf"] = {"elf": elf, "sha256": hashlib.sha256(Path(elf).read_bytes()).hexdigest()}
    if mode in ("named", "legacy", "legacy-missing"):
        rule["map_btf"].update(key_type="u32", value_type="record")
    if mode == "legacy-missing":
        rule["map_btf"]["value_type"] = "record___new"
    if mode == "named":
        # A same-size reordered type must not override a typed ELF definition.
        rule["map_btf"]["value_type"] = "record___other"
    (d / "rules.json").write_text(json.dumps([rule]) + "\n")
    load = command([ninja, "inject-run", "--fail-closed", "--config", str(d / "rules.json"),
                    "--hooks-json", str(d / "hooks.json"), "--", loader, elf, str(d),
                    "typed" if mode == "existing-btf" else "untyped"], d, "load", True)
    capture = None
    try:
        if mode in ("existing-btf", "legacy-missing", "named"):
            rc = load.wait(timeout=30)
            (d / "load.exit").write_text(str(rc) + "\n")
            expected = {"existing-btf": "already has BTF", "legacy-missing": 'map_btf.value_type "record___new" missing',
                        "named": "would replace the ELF map's declared type"}[mode]
            check(rc == 2 and expected in (d / "load.stderr").read_text(), f"{mode}: expected refusal {expected}, rc={rc}")
            if mode != "existing-btf":
                check((d / "map-btf.txt").read_text() == "BTFID=0\n", f"{mode}: map unexpectedly has BTF")
            check(not (d / "ready").exists(), f"{mode}: loader became ready")
            check(json.loads((d / "hooks.json").read_text())["programs"] == [], f"{mode}: hooks were created")
            (d / "PASS").write_text("PASS\n")
            continue
        wait_for(lambda: (d / "ready").exists(), load)
        check((d / "map-btf.txt").read_text() == "BTFID=0\n", f"{mode}: map unexpectedly has BTF")
        pid = (d / "ready").read_text()
        rc = command([ninja, "-p", pid, "--func", "observe", "--list-params", "--members"], d, "members")
        check(rc == 0, f"{mode}: member listing failed, rc={rc}")
        schema = (d / "members.stderr").read_text() + (d / "members.stdout").read_text()
        if mode == "without":
            check("value->identity" not in schema and "bytes" in schema, f"{mode}: expected opaque byte arguments: {schema}")
            rc = command([ninja, "-p", pid, "--func", "observe", "--arg-filter", "value->identity==7",
                          "-w", str(d / "negative.pcapng")], d, "filter-negative")
            check(rc != 0 and 'member "identity" not found' in (d / "filter-negative.stderr").read_text(), f"{mode}: missing-member filter was not refused, rc={rc}")
        else:
            check(any(line.split() == ["value->identity", "u32", "off", "0", "size", "4", "unsigned", "filterable"]
                       for line in schema.splitlines()), schema)
            capture = command([ninja, "-p", pid, "--func", "observe", "--arg-filter", "value->identity==7",
                               "--ringbuf-size", "2", "-w", str(d / "selected.pcapng"), "-v"], d, "capture", True)
            wait_for(lambda: "capturing (" in (d / "capture.stderr").read_text(), capture)
        (d / "trigger").touch()
        wait_for(lambda: len((d / "load.stdout").read_text().splitlines()) == 3, load)
        if capture:
            time.sleep(0.5)
            capture.send_signal(signal.SIGINT)
            rc = capture.wait(timeout=20)
            (d / "capture.exit").write_text(str(rc) + "\n")
            check(rc == 0, f"{mode}: capture failed, rc={rc}")
            counters = (d / "capture.stderr").read_text()
            check("selected=2 exported=2" in counters and "consumed=2 written=2" in counters, f"{mode}: incorrect capture counters: {counters}")
            for counter in ("ringbuf_reserve_fail", "copy_fail", "malformed", "persistence_unconfirmed"):
                check(counter + "=0" in counters, f"{mode}: nonzero loss counter {counter}: {counters}")
            actual = packets(d / "selected.pcapng")
            check(sorted(actual) == [bytes([0xa0]) * 64, bytes([0xa2]) * 64], actual)
        (d / "stop").touch()
        rc = load.wait(timeout=20)
        (d / "load.exit").write_text(str(rc) + "\n")
        check(rc == 0, f"{mode}: loader failed, rc={rc}")
        (d / "PASS").write_text("PASS\n")
    finally:
        for name, proc in (("capture", capture), ("load", load)):
            if proc and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            if proc:
                (d / (name + ".exit")).write_text(str(proc.returncode) + "\n")
(out / "PASS").write_text("PASS: baseline refusal; ELF member capture and typed override refusal; legacy exact selection amid flavors; missing exact name and existing BTF refusal\n")
print((out / "PASS").read_text(), end="")

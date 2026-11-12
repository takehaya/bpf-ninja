#!/usr/bin/env python3
"""Check one case of the follow scenario: the capture's pcap and stderr
against what the loader sent on each generation."""
import argparse
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import assert_pcap  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["held", "polling", "unresolved", "contended"])
    parser.add_argument("dir", type=Path)
    args = parser.parse_args()
    done = dict(field.split("=") for field in (args.dir / "done").read_text().split())
    if args.case == "contended":
        errors = [(args.dir / f"cap-{label}.err").read_text() for label in ("a", "b")]
        statuses = [[line for line in stderr.splitlines() if line.startswith("capture status=")] for stderr in errors]
        complete = [status for status in statuses if len(status) == 1 and status[0].startswith("capture status=complete ")]
        incomplete = [status for status in statuses if len(status) == 1 and status[0].startswith("capture status=incomplete ")]
        combined = "\n".join(errors)
        gaps = re.findall(r"FOLLOW GAP: prog=(\d+) func=(\S+) reason=(\S+) unobserved_ms=(\d+)", combined)
        failures = []
        if done.get("links2") != "1":
            failures.append(f"generation 2 has {done.get('links2')} tracing links, want 1")
        if len(complete) != 1 or "follow_attached=1 follow_held=1 follow_gaps=0" not in complete[0][0]:
            failures.append(f"one complete winner, got {statuses}")
        if len(incomplete) != 1 or "follow_attached=0 follow_held=0 follow_gaps=1" not in incomplete[0][0]:
            failures.append(f"one incomplete loser, got {statuses}")
        id2 = done["id2"]
        if len(gaps) != 1 or gaps[0][0:3] != (id2, "ninja_policies", "observed_by_other"):
            failures.append(f"one observed_by_other gap for generation 2, got {gaps}")
        for failure in failures:
            print(f"FAIL contended: {failure}", file=sys.stderr)
        if failures:
            print(combined, file=sys.stderr)
            return 1
        print(f"PASS contended: id2={id2} links2=1")
        return 0
    total, first2, id2 = int(done["total"]), int(done["first_gen2_seq"]), int(done["id2"])
    stderr = (args.dir / "cap.err").read_text()
    packets = list(assert_pcap.packets(args.dir / "cap.pcap"))
    seqs = [struct.unpack_from(">H", p["data"], 18)[0] for p in packets]
    interfaces = {p["interface"] for p in packets}
    status = [line for line in stderr.splitlines() if line.startswith("capture status=")]
    gaps = re.findall(r"FOLLOW GAP: prog=(\d+) func=(\S+) reason=(\S+) unobserved_ms=(\d+)", stderr)
    missing = sorted(set(range(total)) - set(seqs))
    span = f"{missing[0]}..{missing[-1]}" if missing else "none"
    print(f"{args.case}: sent={total} first_gen2_seq={first2} id2={id2} captured={len(seqs)} "
          f"missing={len(missing)} ({span}) gaps={gaps}")
    print(status[-1] if status else "no status line")
    failures = []

    def expect(ok, message):
        if not ok:
            failures.append(message)

    expect(len(status) == 1, "exactly one status line")
    expect(len(seqs) == len(set(seqs)), "no packet is captured twice")
    expect(all(seq < total for seq in seqs), "only sent packets are captured")
    expect(len(interfaces) == 1, f"one pcapng interface, got {sorted(interfaces)}")
    # Generation 1 was observed from before the first packet.
    expect(all(seq >= first2 for seq in missing), "no generation 1 packet is missing")
    expect(status and status[0].startswith("capture status=incomplete "), "status is incomplete")
    field = dict(f.split("=", 1) for f in status[0].split()[1:]) if status else {}
    if args.case == "held":
        # inject-run kept the loader stopped until the capture had attached
        # to generation 2, so nothing is missing and nothing is reported.
        failures.clear()
        expect(len(status) == 1 and status[0].startswith("capture status=complete "), "status is complete")
        expect(not missing, "no packet is missing")
        expect(not gaps, "no gap is reported")
        expect(len(seqs) == len(set(seqs)) == total, "every packet is captured once")
        expect(len(interfaces) == 1, f"one pcapng interface, got {sorted(interfaces)}")
        expect(field.get("follow_attached") == "1" and field.get("follow_held") == "1" and field.get("follow_gaps") == "0",
               "follow_attached=1 follow_held=1 follow_gaps=0")
        inject = (args.dir / "inject.err").read_text()
        expect(f"(id={id2}): held the load" in inject and "for 1 of 1 following captures" in inject,
               "inject-run held generation 2's load for the capture")
    elif args.case == "polling":
        # The capture finds generation 2 by polling, so the attach is late:
        # generation 2 packets before it may be missing, and it must say so.
        expect(gaps == [(str(id2), "ninja_policies", "late", gaps[0][3])] if gaps else False,
               "one late gap for generation 2")
        expect(total - 1 in seqs, "the last packet, on generation 2, is captured")
        expect(field.get("follow_attached") == "1" and field.get("follow_gaps") == "1",
               "follow_attached=1 follow_gaps=1")
    else:
        # Generation 2 has no value->port, so it cannot be observed.
        expect(gaps == [(str(id2), "ninja_policies", "filter_unresolved", gaps[0][3])] if gaps else False,
               "one filter_unresolved gap for generation 2")
        expect(sorted(seqs) == list(range(first2)), "exactly the generation 1 packets are captured")
        expect(field.get("follow_attached") == "0" and field.get("follow_gaps") == "1",
               "follow_attached=0 follow_gaps=1")
    for failure in failures:
        print(f"FAIL {args.case}: {failure}", file=sys.stderr)
    if failures:
        print(stderr, file=sys.stderr)
        return 1
    print(f"PASS {args.case}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

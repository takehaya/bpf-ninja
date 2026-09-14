#!/usr/bin/env python3
"""Reject private document paths in the index or commits about to be published."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def git(*args):
    result = subprocess.run(["git", *args], capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result.stdout.decode(errors="surrogateescape")


class Checker:
    def __init__(self):
        self.root = Path(git("rev-parse", "--show-toplevel").strip())
        policy = json.loads((self.root / ".public-content-policy.json").read_text())
        self.paths = policy["forbidden_paths"]
        if not self.paths or any(not p or p.startswith("/") or ".." in p.split("/") for p in self.paths):
            raise ValueError("Invalid public content policy")
        self.baseline = policy["history_baseline"]
        self.checked = set()

    def check_paths(self, paths, label):
        bad = []
        for path in paths:
            for rule in self.paths:
                if path == rule.rstrip("/") or (rule.endswith("/") and path.startswith(rule)):
                    bad.append(path)
                    break
        if bad:
            names = "\n".join(f"  {path!r}" for path in sorted(set(bad))[:20])
            raise ValueError(f"Private document paths in {label}:\n{names}\nKeep drafts in the private repository; publish selected files under docs/publications/.")

    def index(self):
        self.check_paths(git("ls-files", "--cached", "-z").split("\0"), "the index")

    def commit(self, revision):
        if not revision or revision.startswith("-"):
            raise ValueError("Invalid revision")
        return git("rev-parse", "--verify", revision + "^{commit}").strip()

    def tree(self, commit):
        if commit not in self.checked:
            self.check_paths(git("ls-tree", "-r", "--name-only", "-z", commit).split("\0"), commit[:12])
            self.checked.add(commit)

    def history(self, head, base=None):
        if git("rev-parse", "--is-shallow-repository").strip() == "true":
            raise ValueError("Full history is required; fetch with --unshallow before checking publication")
        tip = self.commit(head)
        floor = self.commit(self.baseline)
        exclusions = ["^" + floor]
        if base and set(base) != {"0"}:
            exclusions.append("^" + self.commit(base))
        # Always check the tip, even when it is already on the remote.
        self.tree(tip)
        for commit in git("rev-list", tip, *exclusions).splitlines():
            self.tree(commit)

    def pre_push(self, stream):
        for line in stream:
            fields = line.split()
            if len(fields) != 4:
                raise ValueError("Malformed pre-push input")
            local_ref, local_oid, remote_ref, remote_oid = fields
            if not all(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) for oid in (local_oid, remote_oid)):
                raise ValueError("Malformed object ID in pre-push input")
            if set(local_oid) == {"0"}:
                continue  # Deleting a ref uploads no new content.
            self.history(local_oid, remote_oid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--index", action="store_true")
    mode.add_argument("--pre-push", action="store_true")
    mode.add_argument("--head", help="Check this commit and its newly introduced history")
    parser.add_argument("--base", help="Previously published commit; new refs use the policy baseline")
    args = parser.parse_args()
    try:
        checker = Checker()
        if args.index:
            checker.index()
        elif args.pre_push:
            checker.pre_push(sys.stdin)
        else:
            checker.history(args.head, args.base)
    except (ValueError, OSError, KeyError) as exc:
        print(f"Public content check failed: {exc}", file=sys.stderr)
        return 1
    print("Public content check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

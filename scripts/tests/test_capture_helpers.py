"""Lifecycle fault injection for the shell integration helpers; no root needed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/test/run_tests.sh"
FAKE = '''#!/usr/bin/python3
import os, signal, sys, time
case = os.environ["FAKE_CAPTURE_CASE"]
if case in ("parse-error", "attach-error"):
    print("error: " + case, file=sys.stderr, flush=True)
    sys.exit(2)
if case == "no-ready":
    print("0 packets captured", file=sys.stderr, flush=True)
    sys.exit(0)
def finish(signum, frame):
    if case != "no-summary":
        print(("1" if case == "nonzero" else "0") + " packets captured", file=sys.stderr, flush=True)
    if case == "duplicate":
        print("0 packets captured", file=sys.stderr, flush=True)
    sys.exit(42 if case == "exit42" else 0)
signal.signal(signal.SIGTERM, finish)
print("capturing (fake, sharded, 1 shards via reader)...", file=sys.stderr, flush=True)
while True:
    if os.path.exists(os.environ["SENT_MARKER"]):
        if case in ("count", "count-small"):
            print(("3" if case == "count" else "2") + " packets captured", file=sys.stderr, flush=True)
            sys.exit(0)
        if case == "early-summary":
            finish(None, None)
    time.sleep(0.01)
'''


class CaptureHelperTests(unittest.TestCase):
    def exercise(self, scenario, expected_success, helper="run_nomatch_test"):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fake = temp / "capture"
            fake.write_text(FAKE)
            fake.chmod(0o755)
            binary = {"false": "/bin/false", "missing": str(temp / "absent")}.get(scenario, str(fake))
            marker = temp / "sent"
            env = dict(os.environ, BINARY=binary, FAKE_CAPTURE_CASE=scenario,
                       SENT_MARKER=str(marker), CAPTURE_READY_POLLS="20", CAPTURE_SETTLE="0.1",
                       CAPTURE_TIMEOUT="0.5" if scenario == "deadline-summary" else "3")
            result = subprocess.run([
                "bash", "-c", '''source "$1"
                send_packets() {
                    touch "$SENT_MARKER"
                    [[ "$FAKE_CAPTURE_CASE" != sender-error ]]
                }
                if [[ "$2" == run_count_test ]]; then
                    expected=3
                    [[ "$FAKE_CAPTURE_CASE" != deadline-summary ]] || expected=0
                    "$2" "$expected"
                else "$2"; fi
                ''', "test", str(RUNNER), helper], env=env, text=True, capture_output=True, timeout=8)
            self.assertEqual(result.returncode == 0, expected_success, result.stdout + result.stderr)
            if scenario in ("false", "missing", "parse-error", "attach-error", "no-ready"):
                self.assertFalse(marker.exists(), "traffic sent before readiness")
            if expected_success:
                self.assertTrue(marker.exists(), "capture passed without sending traffic")

    def test_negative_lifecycle(self):
        for scenario in ("false", "missing", "parse-error", "attach-error", "no-ready",
                         "no-summary", "exit42", "duplicate", "early-summary", "nonzero", "sender-error"):
            with self.subTest(scenario=scenario):
                self.exercise(scenario, False)
        self.exercise("zero", True)

    def test_count_lifecycle(self):
        self.exercise("count", True, "run_count_test")
        self.exercise("count-small", False, "run_count_test")
        self.exercise("deadline-summary", False, "run_count_test")

    def test_skip_requires_explicit_status(self):
        for ci, failures, skips in (("false", 1, 1), ("true", 2, 0)):
            with self.subTest(ci=ci):
                result = subprocess.run(["bash", "-c", '''source "$1"
            run_test injected bash -c 'echo skipping; exit 1'
            [[ $FAIL -eq 1 && $SKIP -eq 0 ]] || exit 1
            run_test optional bash -c 'exit 77'
            [[ $FAIL -eq $2 && $SKIP -eq $3 ]]
            ''', "test", str(RUNNER), str(failures), str(skips)],
                    env=dict(os.environ, CI=ci), text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

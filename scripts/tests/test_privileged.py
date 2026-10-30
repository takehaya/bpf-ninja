import importlib.util
import io
import json
import subprocess
from pathlib import Path
import unittest
from unittest import mock

path = Path(__file__).resolve().parents[1] / "test/privileged.py"
spec = importlib.util.spec_from_file_location("privileged", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AuditTests(unittest.TestCase):
    def test_missing_or_skipped_required_test_fails(self):
        key = (module.PROGRAM, "TestVlanUntagAtTCIngress")
        self.assertTrue(module.audit([], {key}, None))
        events = [{"Package": key[0], "Test": key[1], "Action": "skip"},
                  {"Package": key[0], "Action": "pass"}]
        self.assertTrue(module.audit(events, {key}, None))
        events[0]["Action"] = "pass"
        self.assertEqual(module.audit(events, {key}, None), [])

    def test_capability_exception_requires_test_kernel_and_reason(self):
        key = (module.PROGRAM, "TestBpfEntryWithDSLFilterNetfilter")
        reason = "BPF_PROG_TYPE_NETFILTER not supported"
        self.assertTrue(module.allowed_skip(*key, reason, "6.1"))
        self.assertFalse(module.allowed_skip(*key, reason, "6.6"))
        self.assertFalse(module.allowed_skip(*key, "unexpected verifier failure", "6.1"))
        self.assertFalse(module.allowed_skip(key[0], "TestOther", reason, "6.1"))

    def test_subtest_skip_is_not_hidden_by_parent_pass(self):
        package, test = module.PROGRAM, "TestBpfFilterSetTC"
        events = [{"Package": package, "Test": test+"/F1", "Action": "skip"},
                  {"Package": package, "Test": test, "Action": "pass"},
                  {"Package": package, "Action": "pass"}]
        self.assertTrue(module.audit(events, {(package, test)}, "6.12"))

    def test_reentry_skip_requires_subtest_kernel_and_reason(self):
        reason = "neither tcx nor clsact available (operation not supported)"
        for parent in ("TestBpfGatedReentry", "TestBpfExtensionReentry"):
            test = parent + "/both"
            self.assertTrue(module.allowed_skip(module.PROGRAM, test, reason, "6.1"))
            for package, name, message, kernel in (
                (module.PROGRAM, test, reason, "6.6"),
                (module.PROGRAM, test, reason, None),
                (module.PROGRAM, test, "unexpected verifier failure", "6.1"),
                (module.PROGRAM, parent, reason, "6.1"),
                ("other/package", test, reason, "6.1"),
            ):
                self.assertFalse(module.allowed_skip(package, name, message, kernel))

    def test_multipoint_netfilter_skip_is_specific(self):
        test = "TestBpfMultiPointLoad/netfilter-entry"
        reason = "BPF_PROG_TYPE_NETFILTER not supported"
        self.assertTrue(module.allowed_skip(module.PROGRAM, test, reason, "6.1"))
        for name, message, kernel in ((test, reason, "6.6"), (test, "verifier failure", "6.1"), ("TestBpfMultiPointLoad", reason, "6.1")):
            self.assertFalse(module.allowed_skip(module.PROGRAM, name, message, kernel))

    def test_inject_untrusted_skip_is_specific(self):
        reason = "skipping: kernel lacks arg:untrusted: program p: load program"
        allowed = ("TestBpfLookupInjectionReadOnlyMap", "TestBpfLookupInjectionMapInMap",
                   "TestBpfLookupInjectionGenericKinds", "TestBpfDispatch", "TestBpfDispatchTC")
        for test in allowed + ("TestBpfLookupInjectionGenericKinds/xskmap",):
            for kernel in ("6.1", "6.6", "6.12", "6.15"):
                self.assertTrue(module.allowed_skip(module.INJECT, test, reason, kernel))
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "6.18"))
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, None))
            self.assertFalse(module.allowed_skip(module.INJECT, test, "verifier rejected a program that should load", "6.1"))
        for test in ("TestBpfLookupInjectionReadOnlyMapCopy", "TestBpfLookupInjectionReadOnlyMapStatic",
                     "TestBpfLookupInjectionMapInMapStatic", "TestBpfLookupInjectionGenericKindsStatic",
                     "TestBpfDispatchStatic", "TestBpfDispatchTCStatic", "TestBpfDispatchStackLimit", "TestBpfTailCallHooks"):
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "6.1"))
        self.assertFalse(module.allowed_skip(module.PROGRAM, allowed[0], reason, "6.1"))

    def test_inject_callback_tail_call_skip_is_specific(self):
        reason = "kernel forbids tail calls in callbacks: cannot tail call within callback"
        for test in ("TestBpfStackLimitsAcrossCalls/callback", "TestBpfStackLimitsAcrossCalls/callback-global"):
            self.assertTrue(module.allowed_skip(module.INJECT, test, reason, "7.3-rc4"))
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "7.2"))
            self.assertFalse(module.allowed_skip(module.INJECT, test, "verifier rejected a program that should load", "7.3-rc4"))
        for test in ("TestBpfStackLimitsAcrossCalls", "TestBpfStackLimitsAcrossCalls/combined"):
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "7.3-rc4"))


class RunnerTests(unittest.TestCase):
    def test_syscallhook_binary_requires_both_tests_and_no_skips(self):
        passed = "--- PASS: TestIntegrationMapTypes (0.01s)\n--- PASS: TestIntegrationLoader (0.01s)\n"
        for output, code, expected in (
            (passed, 0, 0),
            (passed.replace("PASS: TestIntegrationMapTypes", "SKIP: TestIntegrationMapTypes"), 0, 1),
            (passed + "    --- SKIP: TestIntegrationMapTypes/hook-map-types (0.00s)\n", 0, 1),
            ("--- PASS: TestIntegrationLoader (0.01s)\n", 0, 1),
            (passed, 1, 1),
            ("testing: warning: no tests to run\nPASS\n", 0, 1),
        ):
            with self.subTest(output=output, code=code), \
                    mock.patch.object(module.subprocess, "Popen") as popen, \
                    mock.patch("builtins.open", mock.mock_open()), \
                    mock.patch("builtins.print"):
                popen.return_value.__enter__.return_value = mock.Mock(
                    stdout=io.StringIO(output), wait=mock.Mock(return_value=code),
                )
                self.assertEqual(module.syscallhook_suite("./syscallhook.test", "unused.log"), expected)
                command = popen.call_args.args[0]
                self.assertIn("-test.count=1", command)
                self.assertIn("-test.run=^TestIntegration(MapTypes|Loader)$", command)

    def test_libpcap_tag_used_for_listing_and_running(self):
        package, test = module.PROGRAM, "TestBpfLegacy"
        listing = subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "Package": package, "Output": test + "\n",
        }))
        events = [
            {"Package": package, "Test": test, "Action": "pass"},
            {"Package": package, "Action": "pass"},
        ]
        with mock.patch.object(module.sys, "argv", ["privileged.py", "--kernel", "6.1"]), \
                mock.patch.object(module.subprocess, "run", return_value=listing) as listing_run, \
                mock.patch.object(module.subprocess, "Popen") as popen, \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch("builtins.print"):
            # A fresh stream is needed for each suite.
            popen.return_value.__enter__.side_effect = lambda: mock.Mock(
                stdout=io.StringIO("".join(json.dumps(e) + "\n" for e in events)),
                wait=mock.Mock(return_value=0),
            )
            self.assertEqual(module.main(), 0)
        self.assertEqual(listing_run.call_count, 6)
        self.assertEqual(popen.call_count, 6)
        for call in listing_run.call_args_list + popen.call_args_list:
            command = call.args[0]
            start = command.index("go")
            self.assertEqual(command[start:start+4], ["go", "test", "-tags", "enable_libpcap"])
            self.assertEqual(call.kwargs["env"]["CGO_ENABLED"], "1")

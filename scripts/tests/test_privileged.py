import importlib.util
from pathlib import Path
import unittest

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
                   "TestBpfLookupInjectionGenericKinds")
        for test in allowed + ("TestBpfLookupInjectionGenericKinds/xskmap",):
            for kernel in ("6.1", "6.6", "6.12", "6.15"):
                self.assertTrue(module.allowed_skip(module.INJECT, test, reason, kernel))
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "6.18"))
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, None))
            self.assertFalse(module.allowed_skip(module.INJECT, test, "verifier rejected a program that should load", "6.1"))
        for test in ("TestBpfLookupInjectionReadOnlyMapCopy", "TestBpfLookupInjectionReadOnlyMapStatic",
                     "TestBpfLookupInjectionMapInMapStatic", "TestBpfLookupInjectionGenericKindsStatic",
                     "TestBpfTailCallHooks"):
            self.assertFalse(module.allowed_skip(module.INJECT, test, reason, "6.1"))
        self.assertFalse(module.allowed_skip(module.PROGRAM, allowed[0], reason, "6.1"))

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

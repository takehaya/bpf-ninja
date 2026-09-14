"""Exercise actual Git indexes and histories, without changing the working repo."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-public-content.py"
ZERO = "0" * 40


class PublicContentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "core.hooksPath", "/dev/null")
        self.write("README.md", "Public\n")
        self.baseline = self.commit()
        self.write(".public-content-policy.json", json.dumps({
            "history_baseline": self.baseline,
            "forbidden_paths": ["private/", "docs/paper/", "issues/"],
        }))
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.PIPE).decode().strip()

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def check(self, *args, data=None, passed=True):
        result = subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.root,
                                input=data, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, passed, result.stdout + result.stderr)
        return result

    def test_public_publication_and_similar_name_allowed(self):
        self.write("docs/publications/workshop/README.md", "Published")
        self.write("private-example.md", "Public")
        self.commit()
        self.check("--index")
        self.check("--head", "HEAD")

    def test_force_added_ignored_file_rejected(self):
        self.write(".gitignore", "/private/\n")
        self.write("private/a note\nwith newline.md", "Draft")
        self.git("add", "-f", "private")
        self.check("--index", passed=False)

    def test_reserved_directory_symlink_rejected(self):
        os.symlink("/outside/private-docs", self.root / "private")
        self.git("add", "private")
        self.check("--index", passed=False)

    def test_added_then_deleted_in_history_rejected(self):
        self.write("docs/paper/draft.md", "Draft")
        self.commit()
        self.git("rm", "-qr", "docs/paper")
        self.commit()
        self.check("--index")
        self.check("--head", "HEAD", "--base", self.baseline, passed=False)

    def test_new_branch_checks_hidden_history(self):
        self.write("private/draft", "Draft")
        self.commit()
        self.git("rm", "-qr", "private")
        head = self.commit()
        self.check("--pre-push", data=f"refs/heads/new {head} refs/heads/new {ZERO}\n", passed=False)

    def test_annotated_tag_and_multiple_refs(self):
        good = self.git("rev-parse", "HEAD")
        self.write("issues/draft", "Draft")
        self.commit()
        self.git("tag", "-am", "Draft", "draft-tag")
        tag = self.git("rev-parse", "draft-tag")
        self.check("--pre-push", data=f"refs/heads/main {good} refs/heads/main {ZERO}\nrefs/tags/draft-tag {tag} refs/tags/draft-tag {ZERO}\n", passed=False)

    def test_deleted_ref_allowed(self):
        self.check("--pre-push", data=f"(delete) {ZERO} refs/heads/old {self.baseline}\n")

    def test_unknown_remote_commit_fails(self):
        head = self.git("rev-parse", "HEAD")
        self.check("--pre-push", data=f"refs/heads/main {head} refs/heads/main {'1' * 40}\n", passed=False)

    def test_malformed_push_fails(self):
        self.check("--pre-push", data="unexpected\n", passed=False)

    def test_merge_side_branch_inspected(self):
        self.git("checkout", "-qb", "side")
        self.write("private/draft", "Draft")
        self.commit()
        self.git("rm", "-qr", "private")
        self.commit()
        self.git("checkout", "-q", "main")
        self.git("merge", "--no-ff", "-qm", "merge", "side")
        self.check("--head", "HEAD", passed=False)


if __name__ == "__main__":
    unittest.main()

"""Tests for the one-file offline verifier. Author: Gavin Blacklock."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(CODE_DIR, "verifier", "verify.py")
FIXTURES = os.path.join(CODE_DIR, "fixtures")
SECRET_FILE = os.path.join(FIXTURES, "test_secret.txt")


def run_verifier(bundle_path, *extra):
    return subprocess.run(
        [sys.executable, VERIFIER, bundle_path,
         "--secret-file", SECRET_FILE, "--key-id", "acta-test-key-1",
         *extra],
        capture_output=True, text=True,
    )


def bundle_path(fixture_name):
    with open(os.path.join(FIXTURES, fixture_name),
              encoding="utf-8") as handle:
        fixture = json.load(handle)
    handle_fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(handle_fd, "w", encoding="utf-8") as out:
        json.dump(fixture["bundle"], out)
    return path


class TestOfflineVerifier(unittest.TestCase):
    def test_valid_fixture_passes(self):
        result = run_verifier(bundle_path("fixture_01_valid_chain.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("PASS"), result.stdout)

    def test_tampered_fixture_fails_with_location(self):
        result = run_verifier(bundle_path("fixture_02_tampered_receipt.json"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("receipt 1", result.stdout)
        self.assertIn("TAMPERED", result.stdout)

    def test_denial_fixture_fails_with_reason_code(self):
        result = run_verifier(
            bundle_path("fixture_04_denial_without_reason_code.json"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("DENIAL_REASON_MISSING", result.stdout)

    def test_verifier_is_self_contained(self):
        with open(VERIFIER, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("from acta", source)
        self.assertNotIn("import acta", source)
        self.assertNotIn("from institutio", source)


if __name__ == "__main__":
    unittest.main()

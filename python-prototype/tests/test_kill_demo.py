"""Tests for the Provable Kill demo script. Author: Gavin Blacklock."""

import os
import subprocess
import sys
import unittest

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestProvableKillDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = subprocess.run(
            [sys.executable, os.path.join(CODE_DIR, "demo_provable_kill.py")],
            capture_output=True, text=True,
        )
        cls.out = cls.result.stdout + cls.result.stderr

    def test_demo_exits_zero(self):
        self.assertEqual(self.result.returncode, 0, self.out)
        self.assertIn("DEMO RESULT: PASS", self.out)

    def test_three_denials_all_revoked(self):
        for label in ("a", "b", "c"):
            self.assertIn("attempt (%s)" % label, self.out)
        self.assertIn("3 post-kill denials (all reason revoked)", self.out)

    def test_kill_burn_and_sibling_continuity_reported(self):
        self.assertIn("KILL-BURN receipt", self.out)
        self.assertIn("sibling Standing checkpoint recomputes "
                      "unchanged", self.out)
        self.assertIn("sibling post-kill action: ALLOW", self.out)

    def test_standalone_verifier_passes_on_the_bundle(self):
        self.assertIn("standalone verifier: PASS", self.out)


if __name__ == "__main__":
    unittest.main()

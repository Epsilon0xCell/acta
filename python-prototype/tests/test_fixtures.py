"""Tests that every shipped fixture matches its expected verdict.

Author: Gavin Blacklock
"""

import os
import subprocess
import sys
import unittest

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestFixtures(unittest.TestCase):
    def test_fixture_runner_all_pass(self):
        result = subprocess.run(
            [sys.executable, os.path.join(CODE_DIR, "fixtures",
                                          "run_fixtures.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("34 passed", result.stdout)


if __name__ == "__main__":
    unittest.main()

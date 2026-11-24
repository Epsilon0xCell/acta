"""Phase 1 fixture corpus expansion: permanence tests.

Author: Gavin Blacklock

The corpus grew from 16 fixtures to the blueprint's full set:
30 enumerated fixtures plus the Provable Kill family K1 to K4,
34 fixture files in total (fixtures 17 to 34 added 2026-11-23;
K4 predates the expansion as fixture 12). These tests pin the
new total in both runners, pin the new fixture kinds (checkpoint
and charter_chain) in the Python runner, and pin the new
Standing fixtures (23, 24, and K1 as fixture 32) as permanent
members of the cross-implementation differential suite: the Rust
conformance runner must report each of them as spec conformance,
never as prototype-parameter conformance and never as a skip.
The blueprint-to-fixture mapping and its reconciliations live
in CORPUS-INDEX.md at the programme root.
"""

import importlib.util
import os
import subprocess
import sys
import unittest

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(CODE_DIR, "fixtures")
RUST_DIR = os.path.join(os.path.dirname(CODE_DIR), "code-rust")
SECRET_FILE = os.path.join(FIXTURES_DIR, "test_secret.txt")


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "run_fixtures", os.path.join(FIXTURES_DIR, "run_fixtures.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestFixtureExpansionPython(unittest.TestCase):
    def test_python_runner_reports_34_passed(self):
        result = subprocess.run(
            [sys.executable, os.path.join(FIXTURES_DIR, "run_fixtures.py")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fixtures: 34 run, 34 passed, 0 failed",
                      result.stdout)

    def test_new_kinds_pass_in_python_runner(self):
        runner = load_runner()
        for name in (
            "fixture_25_checkpoint_witness_below_quorum.json",
            "fixture_26_checkpoint_witness_quorum_met.json",
            "fixture_27_checkpoint_head_of_other_chain.json",
            "fixture_29_charter_succession_chain_valid.json",
            "fixture_30_charter_amendment_broken_link.json",
        ):
            ok, detail = runner.check_fixture(
                os.path.join(FIXTURES_DIR, name))
            self.assertTrue(ok, "%s: %s" % (name, detail))

    def test_kill_family_files_present(self):
        for name in (
            "fixture_12_kill_by_wrong_key.json",
            "fixture_31_kill_switch_halt_then_denial.json",
            "fixture_32_k1_kill_is_absorbing.json",
            "fixture_33_k2_replay_after_revocation.json",
            "fixture_34_k3_fork_omitting_kill.json",
        ):
            self.assertTrue(
                os.path.exists(os.path.join(FIXTURES_DIR, name)), name)


class TestFixtureExpansionDifferential(unittest.TestCase):
    def test_rust_conformance_34_and_new_standing_fixtures_are_spec(self):
        cargo = os.path.expanduser("~/.cargo/bin/cargo")
        if not os.path.exists(cargo):
            self.skipTest("cargo not installed; Rust side unverifiable "
                          "in this environment")
        build = subprocess.run(
            [cargo, "build", "--offline", "-p", "acta-verify",
             "--bin", "conformance"],
            cwd=RUST_DIR, capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        binary = os.path.join(RUST_DIR, "target", "debug", "conformance")
        run = subprocess.run([binary, FIXTURES_DIR, SECRET_FILE],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("fixtures: 34 run, 34 passed, 0 failed, 0 skipped",
                      run.stdout)
        for name in (
            "fixture_23_standing_mint_cap_saturation.json",
            "fixture_24_countersignature_missing_no_mint.json",
            "fixture_32_k1_kill_is_absorbing.json",
        ):
            line = next(
                (ln for ln in run.stdout.splitlines() if name in ln), "")
            self.assertIn("spec conformance", line,
                          "%s must run as spec conformance: %s"
                          % (name, line))


if __name__ == "__main__":
    unittest.main()

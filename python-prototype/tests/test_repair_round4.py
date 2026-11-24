"""Regression tests for repair round 4 (third re-audit findings
T1, T2, and minors t3 to t6).

Author: Gavin Blacklock

Each test is named for its finding and encodes the third
re-audit's own probes: the two countersign-requirement encodings
that each tree read and the other ignored (T1), the duplicated
receipt identity the Rust tree accepted (T2), and the residues
of S2, S3, and S5 (negative tally and weight values, boolean and
float policy coercions, the missing-ceiling-curve asymmetry, and
malformed witness policies). The differential cases run the
re-audit's exact probe policies through the Rust conformance
runner as well, so the one definition is proven, not asserted.
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from institutio import (  # noqa: E402
    build_checkpoint, compute_standing, verify_checkpoint,
)
from tests.test_differential import CEILING_CURVE, run_runner  # noqa: E402

HL = 10000000

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_DIR = os.path.join(os.path.dirname(CODE_DIR), "code-rust")
SECRET_FILE = os.path.join(CODE_DIR, "fixtures", "test_secret.txt")


def run_runner_allowing_fail(document):
    """The differential runner without run_runner's exit-code
    assertion: rejection cases are proven by a FAIL line, which
    the runner reports with a non-zero exit."""
    cargo = os.path.expanduser("~/.cargo/bin/cargo")
    if not os.path.exists(cargo):
        return None
    build = subprocess.run(
        [cargo, "build", "--offline", "-p", "acta-verify",
         "--bin", "conformance"],
        cwd=RUST_DIR, capture_output=True, text=True)
    assert build.returncode == 0, build.stdout + build.stderr
    binary = os.path.join(RUST_DIR, "target", "debug", "conformance")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fixture_differential.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        run = subprocess.run([binary, tmp, SECRET_FILE],
                             capture_output=True, text=True)
    return run.stdout


def action(timestamp, risk_weight=10, scope_class="write", **extra):
    doc = {
        "receipt_type": "ACTION", "timestamp": timestamp,
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": scope_class,
                   "risk_weight": risk_weight, "delegation_depth": 0},
    }
    doc.update(extra)
    return doc


def complete_policy(**overrides):
    policy = {
        "ceiling_curve": CEILING_CURVE,
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 1000000,
            "half_life_seconds": HL, "hop_attenuation_ppm": 1000000,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 2, "scope": 2,
                                 "manifest-mismatch": 1, "budget": 1,
                                 "standing-ceiling": 1}}},
    }
    policy.update(overrides)
    return policy


class TestT1CountersignEncoding(unittest.TestCase):
    """Finding T1: one encoding for the countersign requirement,
    Section 16.10 decision 22."""

    def test_T1_spec_form_policy_requires_countersignature(self):
        # The re-audit's Policy A, exactly: the field Section
        # 16.3 item 4 names, one ACTION at risk weight 10, a
        # garbage countersignature, no counterparty keys. This
        # tree once computed Standing 10 (requirement not seen);
        # decision 22's form makes the requirement read, and the
        # unverified signature mints zero.
        policy = complete_policy(
            countersign_policy={"required_for": ["write"]})
        receipts = [action(100, counterparty_id="cp-1",
                           counterparty_sig="AAAA")]
        result = compute_standing(receipts, policy, eval_time=100,
                                  agent_id="agent-1")
        self.assertEqual(result["write"]["standing"], 0)
        self.assertEqual(result["write"]["minted"], 0)

    def test_T1_differently_named_field_is_an_error(self):
        # The re-audit's Policy B: the old Python form. It is not
        # honoured and not ignored; it is a validation error.
        policy = complete_policy(countersign_required=True)
        with self.assertRaises(ValueError) as ctx:
            compute_standing([action(100)], policy, eval_time=100)
        self.assertIn("decision 22", str(ctx.exception))

    def test_T1_per_class_and_other_shapes_are_errors(self):
        # The re-audit's Policy C (per-class form), a bare
        # boolean, and a different inner key: all errors.
        per_class = complete_policy()
        per_class["scope_classes"]["write"]["countersign_required"] = True
        with self.assertRaises(ValueError):
            compute_standing([action(100)], per_class, eval_time=100)
        bare = complete_policy(countersign_policy=True)
        with self.assertRaises(ValueError):
            compute_standing([action(100)], bare, eval_time=100)
        other_key = complete_policy(
            countersign_policy={"classes": ["write"]})
        with self.assertRaises(ValueError):
            compute_standing([action(100)], other_key, eval_time=100)

    def test_T1_differential_spec_form_policy(self):
        # The same Policy A through the Rust runner: spec
        # conformance at Standing 0, as this tree computes.
        policy = complete_policy(
            countersign_policy={"required_for": ["write"]})
        receipts = [action(100, counterparty_id="cp-1",
                           counterparty_sig="AAAA")]
        document = {
            "name": "round4_t1_spec_form",
            "kind": "standing",
            "description": "Decision 22 spec-form countersign "
                           "policy (T1): unverified signature "
                           "mints zero in both trees.",
            "agent_id": "agent-1",
            "eval_time": 100,
            "standing_policy": policy,
            "receipts": receipts,
            "expected_standing": {"write": {"standing": 0}},
        }
        out = run_runner(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertIn("PASS fixture_differential.json", out)
        self.assertIn("spec conformance", out)

    def test_T1_differential_python_form_policy_rejected(self):
        # The old Python form through the runner: neither tree
        # may run it as spec conformance (the Rust parser errors;
        # this tree errors, proven above).
        policy = complete_policy(countersign_required=True)
        document = {
            "name": "round4_t1_python_form",
            "kind": "standing",
            "description": "Decision 22: countersign_required is "
                           "not a conforming field name (T1).",
            "agent_id": "agent-1",
            "eval_time": 100,
            "standing_policy": policy,
            "receipts": [action(100)],
            "expected_standing": {"write": {"standing": 0}},
        }
        out = run_runner_allowing_fail(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertNotIn("spec conformance:", out)
        self.assertIn("FAIL fixture_differential.json", out)


class TestT2DuplicateReceiptIdDifferential(unittest.TestCase):
    def test_T2_differential_duplicate_receipt_id_rejected(self):
        # The re-audit's segment: two ACTION receipts, risk
        # weight 10 each, both receipt_id "dup", complete policy.
        # This tree raises; the Rust computation once computed
        # Standing 20 as spec conformance and must now refuse.
        policy = complete_policy()
        receipts = [action(100, receipt_id="dup"),
                    action(110, receipt_id="dup")]
        with self.assertRaises(ValueError) as ctx:
            compute_standing(receipts, policy, eval_time=110,
                             agent_id="agent-1")
        self.assertIn("duplicate receipt_id", str(ctx.exception))
        document = {
            "name": "round4_t2_duplicate_id",
            "kind": "standing",
            "description": "Decision 19: a duplicated receipt_id "
                           "is invalid in both trees (T2).",
            "agent_id": "agent-1",
            "eval_time": 110,
            "standing_policy": policy,
            "receipts": receipts,
            "expected_standing": {"write": {"standing": 20}},
        }
        out = run_runner_allowing_fail(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertIn("FAIL fixture_differential.json", out)


class TestT3StrictPolicyTypes(unittest.TestCase):
    def test_t3_boolean_and_float_policy_values_rejected(self):
        # Minor t3: True read as mint_rate 1 and 1.5 computed in
        # this tree pre-repair; the Rust parser rejects both.
        for bad in (True, 1.5):
            policy = complete_policy()
            policy["scope_classes"]["write"]["mint_rate"] = bad
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(100)], policy, eval_time=100)
        policy = complete_policy()
        policy["scope_classes"]["write"]["burn_unit"] = True
        denial = {"receipt_type": "DENIAL", "timestamp": 100,
                  "reason_code": "budget",
                  "agent": {"id": "agent-1"},
                  "action": {"name": "tool.call",
                             "scope_class": "write"}}
        with self.assertRaises(ValueError):
            compute_standing([denial], policy, eval_time=100)


class TestT4MissingCeilingCurve(unittest.TestCase):
    def test_t4_differential_missing_ceiling_curve(self):
        # Minor t4: decision 23 aligns the rule (the curve is a
        # required field wherever ceilings are produced, and
        # ComputeStanding produces them). This tree errors; the
        # Rust tree may not run the same policy as spec
        # conformance either.
        policy = complete_policy()
        del policy["ceiling_curve"]
        with self.assertRaises(ValueError) as ctx:
            compute_standing([action(100)], policy, eval_time=100)
        self.assertIn("UNSPECIFIED_BY_SPEC", str(ctx.exception))
        document = {
            "name": "round4_t4_missing_curve",
            "kind": "standing",
            "description": "Decision 23: no ceiling curve "
                           "anywhere is an incomplete policy "
                           "in both trees (t4).",
            "agent_id": "agent-1",
            "eval_time": 100,
            "standing_policy": policy,
            "receipts": [action(100)],
            "expected_standing": {"write": {"standing": 10}},
        }
        out = run_runner(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertNotIn("spec conformance:", out)


class TestT5NegativeValues(unittest.TestCase):
    def test_t5_negative_burn_amount_rejected(self):
        # Minor t5: this tree tallied burn_amount minus 5
        # pre-repair; the Rust prototype path silently dropped
        # it. Both now reject it.
        policy = complete_policy()
        burn = {"receipt_type": "BURN", "timestamp": 100,
                "burn_amount": -5,
                "agent": {"id": "agent-1"},
                "action": {"name": "standing.burn",
                           "scope_class": "write"}}
        with self.assertRaises(ValueError) as ctx:
            compute_standing([burn], policy, eval_time=100)
        self.assertIn("burn_amount", str(ctx.exception))

    def test_t5_negative_risk_weight_rejected(self):
        # Minor t5: a negative risk weight silently computed as
        # zero mint in this tree; the Rust tree rejects it at
        # parse. Both now reject it.
        policy = complete_policy()
        with self.assertRaises(ValueError) as ctx:
            compute_standing([action(100, risk_weight=-3)], policy,
                             eval_time=100)
        self.assertIn("risk_weight", str(ctx.exception))


class TestT6MalformedWitnessPolicy(unittest.TestCase):
    """Minor t6: malformed witness policies are errors in both
    trees (the Rust half is test_t6 in standing_tests.rs)."""

    POLICY = {
        "ceiling_curve": CEILING_CURVE,
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 1000000,
            "half_life_seconds": HL, "hop_attenuation_ppm": 1000000}},
        "witness_policy": {"witness_key_ids": ["w-1", "w-2"],
                           "quorum": 2},
    }

    def _verify(self, witness_policy):
        policy = copy.deepcopy(self.POLICY)
        policy["witness_policy"] = witness_policy
        checkpoint = build_checkpoint(
            [action(10)], self.POLICY, eval_time=10,
            agent_id="agent-1", org_id="org-1",
            charter_hash="c" * 64)
        return verify_checkpoint(
            checkpoint, [action(10)], policy, witness_verifiers={})

    def test_t6_k_alias_and_string_quorum_and_bounds_rejected(self):
        for bad in (
            {"witness_key_ids": ["w-1", "w-2"], "k": 2},
            {"witness_key_ids": ["w-1", "w-2"], "quorum": "2"},
            {"witness_key_ids": ["w-1", "w-2"]},
            {"witness_key_ids": ["w-1", "w-2"], "quorum": 3},
            {"witness_key_ids": ["w-1", "w-2"], "quorum": 0},
        ):
            errors = self._verify(bad)
            self.assertTrue(
                any("witness_policy" in e for e in errors),
                (bad, errors))

    def test_t6_spec_form_witness_policy_still_enforced(self):
        # The well-formed policy is untouched by the strictness:
        # quorum 2 with no verifiable cosignatures still fails
        # as a quorum failure, not a form failure.
        errors = self._verify({"witness_key_ids": ["w-1", "w-2"],
                               "quorum": 2})
        self.assertTrue(any("quorum not met" in e for e in errors),
                        errors)
        self.assertFalse(any("exactly the form" in e for e in errors),
                         errors)


if __name__ == "__main__":
    unittest.main()

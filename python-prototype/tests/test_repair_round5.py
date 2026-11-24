"""Regression tests for repair round 5 (fourth re-audit findings
U1 to U5, the T1 and T2 residues, the S2 and S5 residues, and
observation U6).

Author: Gavin Blacklock

Section 16.10 decision 24 fixes one strictness table for the
acceptance surface: integer, non-negative, non-null, spec-named,
eagerly and class-locally parsed, identically in both trees.
Each test is named for its finding and encodes the fourth
re-audit's own probes. The differential class at the end adds
the re-audit's 27 divergent cases as permanent cases: for every
one, the Python computation raises and the Rust conformance
runner may not run the case as spec conformance (its
prototype-parameter fallback is non-agreement, as the re-audit
counted it).
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from institutio import compute_standing  # noqa: E402
from tests.test_differential import CEILING_CURVE, run_runner  # noqa: E402
from tests.test_repair_round4 import run_runner_allowing_fail  # noqa: E402

HL = 10000000
MULTIPLIERS = {"revoked": 2, "scope": 2, "manifest-mismatch": 1,
               "budget": 1, "standing-ceiling": 1}


def action(timestamp, risk_weight=10, scope_class="write", **extra):
    doc = {
        "receipt_type": "ACTION", "timestamp": timestamp,
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": scope_class,
                   "risk_weight": risk_weight, "delegation_depth": 0},
    }
    doc.update(extra)
    return doc


def denial(timestamp, reason_code="revoked", scope_class="write"):
    return {
        "receipt_type": "DENIAL", "timestamp": timestamp,
        "reason_code": reason_code,
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": scope_class,
                   "risk_weight": 0, "delegation_depth": 0},
    }


def complete_policy(**overrides):
    policy = {
        "ceiling_curve": CEILING_CURVE,
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 100,
            "half_life_seconds": HL, "hop_attenuation_ppm": 1000000,
            "correlated_burn_fraction_ppm": 250000,
            "burn_unit": 5, "burn_multipliers": dict(MULTIPLIERS),
            "severe_reason_codes": ["revoked", "scope"]}},
    }
    policy.update(overrides)
    return policy


def class_field_policy(field, value, scope_class="write"):
    policy = complete_policy()
    policy["scope_classes"][scope_class][field] = value
    return policy


class TestU1NegativePolicyValues(unittest.TestCase):
    """Finding U1 (Major): negative policy integers are errors."""

    def test_U1_negative_burn_never_manufactures_standing(self):
        # The re-audit's exact probe: burn_unit -5, multiplier 2,
        # 10 minted; pre-repair the closed form burned minus 10
        # and Standing read 20.
        policy = class_field_policy("burn_unit", -5)
        policy["scope_classes"]["write"]["burn_multipliers"] = {
            "revoked": 2}
        receipts = [action(10), denial(20)]
        with self.assertRaises(ValueError):
            compute_standing(receipts, policy, eval_time=20)

    def test_U1_negative_multiplier_never_manufactures_standing(self):
        # The second probe: a burn multiplier of -1 burned minus
        # 5 and Standing read 15 on 10 minted.
        policy = complete_policy()
        policy["scope_classes"]["write"]["burn_multipliers"] = {
            "revoked": -1}
        with self.assertRaises(ValueError):
            compute_standing([action(10), denial(20)], policy,
                             eval_time=20)

    def test_U1_every_negative_quantity_field_rejected(self):
        for field in ("mint_rate", "mint_cap_per_epoch",
                      "hop_attenuation_ppm",
                      "correlated_burn_fraction_ppm", "burn_unit",
                      "half_life_seconds"):
            policy = class_field_policy(field, -5)
            with self.assertRaises(ValueError, msg=field):
                compute_standing([action(10)], policy, eval_time=10)
        policy = complete_policy(epoch_seconds=-5)
        with self.assertRaises(ValueError):
            compute_standing([action(10)], policy, eval_time=10)


class TestU2EagerClassLocalParsing(unittest.TestCase):
    """Finding U2 (Major): no top-level merge; whole policy
    validated at load, touched classes or not."""

    def test_U2_top_level_class_fields_do_not_merge(self):
        # The re-audit's probe: mint_rate 3 and the other class
        # fields at the top level, an empty class object. This
        # tree computed Standing 30 by inheritance; Rust stopped
        # as UNSPECIFIED_BY_SPEC, and now this tree does too.
        policy = {
            "ceiling_curve": CEILING_CURVE,
            "mint_rate": 3, "mint_cap_per_epoch": 100,
            "half_life_seconds": HL, "hop_attenuation_ppm": 1000000,
            "scope_classes": {"write": {}},
        }
        with self.assertRaises(ValueError) as ctx:
            compute_standing([action(10, risk_weight=10)], policy,
                             eval_time=10)
        self.assertIn("UNSPECIFIED_BY_SPEC", str(ctx.exception))

    def test_U2_malformed_unused_class_rejected_at_load(self):
        # Boolean and float mint_rate in a class the segment
        # never touches computed the touched class pre-repair;
        # the Rust parser, parsing every class up front, refused.
        for bad in (True, 1.5):
            policy = complete_policy()
            policy["scope_classes"]["read"] = {"mint_rate": bad}
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(10)], policy, eval_time=10)

    def test_U6_list_form_scope_classes_is_a_policy_error(self):
        # Observation U6: a list-form scope_classes crashed with
        # an AttributeError; it is a policy error (decision 9).
        policy = complete_policy(scope_classes=["write"])
        with self.assertRaises(ValueError):
            compute_standing([action(10)], policy, eval_time=10)


class TestU3Nulls(unittest.TestCase):
    """Finding U3: a stated null is malformed, never absent."""

    def test_U3_null_class_fields_rejected(self):
        for field in ("mint_rate", "mint_cap_per_epoch",
                      "hop_attenuation_ppm",
                      "correlated_burn_fraction_ppm", "burn_unit",
                      "half_life_seconds", "ceiling_curve",
                      "burn_multipliers", "severe_reason_codes"):
            policy = class_field_policy(field, None)
            with self.assertRaises(ValueError, msg=field):
                compute_standing([action(10)], policy, eval_time=10)

    def test_U3_null_policy_fields_rejected(self):
        for overrides in ({"epoch_seconds": None},
                          {"diversity_caps": None},
                          {"witness_policy": None},
                          {"ceiling_curve": None},
                          {"scope_classes": None}):
            policy = complete_policy(**overrides)
            with self.assertRaises(ValueError, msg=repr(overrides)):
                compute_standing([action(10)], policy, eval_time=10)
        policy = complete_policy()
        policy["diversity_caps"] = {"per_counterparty_per_epoch": None}
        with self.assertRaises(ValueError):
            compute_standing([action(10)], policy, eval_time=10)


class TestT1CountersignNull(unittest.TestCase):
    def test_T1_countersign_policy_null_is_an_error(self):
        # T1 residue: countersign_policy stated as null minted
        # at full weight here (read as absent) and was a parse
        # error in Rust. Decision 24 row (c) settles it.
        policy = complete_policy(countersign_policy=None)
        with self.assertRaises(ValueError):
            compute_standing([action(10)], policy, eval_time=10)


class TestT2NonStringReceiptId(unittest.TestCase):
    def test_T2_numeric_receipt_id_rejected(self):
        # T2 residue: the re-audit's duplicated numeric identity,
        # and a single numeric identity with it. An identity the
        # computation cannot see as a string is malformed.
        policy = complete_policy()
        receipts = [action(10, receipt_id=123),
                    action(20, receipt_id=123)]
        with self.assertRaises(ValueError):
            compute_standing(receipts, policy, eval_time=20)
        with self.assertRaises(ValueError):
            compute_standing([action(10, receipt_id=123)], policy,
                             eval_time=10)


class TestS2NullReceiptScalars(unittest.TestCase):
    def test_S2_null_risk_weight_rejected(self):
        # S2 residue: a null risk_weight defaulted to 1 in the
        # Rust prototype parser and errored here; both error.
        with self.assertRaises(ValueError):
            compute_standing([action(10, risk_weight=None)],
                             complete_policy(), eval_time=10)

    def test_S2_null_burn_amount_rejected(self):
        # A stated null burn_amount was treated as zero by both
        # trees; decision 24 row (c) makes it malformed in both.
        burn = {"receipt_type": "BURN", "timestamp": 10,
                "burn_amount": None,
                "agent": {"id": "agent-1"},
                "action": {"name": "standing.burn",
                           "scope_class": "write"}}
        with self.assertRaises(ValueError):
            compute_standing([burn], complete_policy(), eval_time=10)


class TestS5WitnessPolicyAtComputation(unittest.TestCase):
    """S5 residue: the computation is not blind to a malformed
    witness policy, and quorum bounds bind at computation."""

    def test_S5_malformed_witness_policy_rejected_at_computation(self):
        for bad in (
            {"witness_key_ids": ["w-1", "w-2"], "k": 2},
            {"witness_key_ids": ["w-1", "w-2"], "quorum": "2"},
            {"witness_key_ids": ["w-1", "w-2"]},
            {"witness_key_ids": [7, "w-2"], "quorum": 1},
            {"witness_key_ids": ["w-1"], "quorum": 1, "extra": 0},
            None,
            ["w-1"],
        ):
            policy = complete_policy(witness_policy=bad)
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(10)], policy, eval_time=10)

    def test_S5_witness_quorum_bounds_checked_at_computation(self):
        for bad in ({"witness_key_ids": ["w-1"], "quorum": 0},
                    {"witness_key_ids": ["w-1"], "quorum": 5}):
            policy = complete_policy(witness_policy=bad)
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(10)], policy, eval_time=10)


class TestU4SevereCodesAlias(unittest.TestCase):
    def test_U4_severe_codes_alias_rejected(self):
        # Finding U4: Rust honoured severe_codes, Python ignored
        # it. Decision 24 row (d): the alias is rejected in both.
        policy = complete_policy()
        policy["scope_classes"]["write"]["severe_codes"] = ["budget"]
        with self.assertRaises(ValueError):
            compute_standing([action(10)], policy, eval_time=10)


class TestU5MalformedTimestamps(unittest.TestCase):
    def test_U5_float_and_string_timestamps_rejected(self):
        # Finding U5: 100.9 and "100" coerced to 100 here (int())
        # and mapped to 0 in Rust; Standing read 5 against 0.
        for bad in (100.9, "100", -5, None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(bad)], complete_policy(),
                                 eval_time=200)

    def test_U5_malformed_eval_time_rejected(self):
        for bad in (100.9, "100", -5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([action(10)], complete_policy(),
                                 eval_time=bad)


def divergent_cases():
    """The fourth re-audit's 27 divergent cases, reconstructed
    from its Section 3: (name, policy, receipts). For every one
    the Python computation raises and the Rust runner may not
    report spec conformance."""
    cases = []
    # Group 1 (6): negative policy integers (U1).
    for field in ("mint_rate", "mint_cap_per_epoch",
                  "hop_attenuation_ppm",
                  "correlated_burn_fraction_ppm", "burn_unit"):
        cases.append(("negative_%s" % field,
                      class_field_policy(field, -5), [action(10)]))
    negative_multiplier = complete_policy()
    negative_multiplier["scope_classes"]["write"][
        "burn_multipliers"] = {"revoked": -1}
    cases.append(("negative_burn_multiplier", negative_multiplier,
                  [action(10), denial(20)]))
    # Group 2 (4): policy scope and timing (U2).
    inherited = {
        "ceiling_curve": CEILING_CURVE,
        "mint_rate": 3, "mint_cap_per_epoch": 100,
        "half_life_seconds": HL, "hop_attenuation_ppm": 1000000,
        "scope_classes": {"write": {}},
    }
    cases.append(("top_level_inheritance", inherited, [action(10)]))
    for index, bad in enumerate((True, 1.5, True)):
        policy = complete_policy()
        policy["scope_classes"]["read"] = {"mint_rate": bad}
        cases.append(("unused_class_malformed_%d" % index, policy,
                      [action(10)]))
    # Group 3 (7): malformed witness policies at computation (S5).
    for index, bad in enumerate((
            {"witness_key_ids": ["w-1", "w-2"], "k": 2},
            {"witness_key_ids": ["w-1", "w-2"], "quorum": "2"},
            {"witness_key_ids": ["w-1", "w-2"]},
            {"witness_key_ids": [7, "w-2"], "quorum": 1},
            {"witness_key_ids": ["w-1"], "quorum": 1, "extra": 0},
            None,
            ["w-1"])):
        cases.append(("witness_malformed_%d" % index,
                      complete_policy(witness_policy=bad),
                      [action(10)]))
    # Group 4 (6): explicit nulls (U3, T1 residue, S2 residue).
    for field in ("mint_cap_per_epoch", "hop_attenuation_ppm",
                  "correlated_burn_fraction_ppm"):
        cases.append(("null_%s" % field,
                      class_field_policy(field, None), [action(10)]))
    cases.append(("null_epoch_seconds",
                  complete_policy(epoch_seconds=None), [action(10)]))
    cases.append(("null_countersign_policy",
                  complete_policy(countersign_policy=None),
                  [action(10)]))
    cases.append(("null_risk_weight", complete_policy(),
                  [action(10, risk_weight=None)]))
    # Group 5 (1): the severe_codes alias (U4).
    alias = complete_policy()
    alias["scope_classes"]["write"]["severe_codes"] = ["budget"]
    cases.append(("severe_codes_alias", alias,
                  [action(10), denial(20, reason_code="budget")]))
    # Group 6 (2): malformed timestamps (U5).
    cases.append(("float_timestamp", complete_policy(),
                  [action(100.9)]))
    cases.append(("string_timestamp", complete_policy(),
                  [action("100")]))
    # Group 7 (1): numeric receipt identity (T2 residue).
    cases.append(("numeric_receipt_id", complete_policy(),
                  [action(10, receipt_id=123),
                   action(20, receipt_id=123)]))
    return cases


class TestRound5DifferentialCases(unittest.TestCase):
    """The 27 divergent cases of the fourth re-audit, permanent."""

    def test_all_27_cases_reconstructible(self):
        self.assertEqual(len(divergent_cases()), 27)

    def test_python_rejects_every_case(self):
        for name, policy, receipts in divergent_cases():
            with self.assertRaises(ValueError, msg=name):
                compute_standing(receipts, policy, eval_time=200)

    def test_rust_never_reports_spec_conformance(self):
        for name, policy, receipts in divergent_cases():
            document = {
                "name": "round5_%s" % name,
                "kind": "standing",
                "description": "Decision 24 strictness case %s: "
                               "rejected in both trees." % name,
                "agent_id": "agent-1",
                "eval_time": 200,
                "standing_policy": policy,
                "receipts": receipts,
                "expected_standing": {"write": {"standing": 0}},
            }
            out = run_runner_allowing_fail(document)
            if out is None:
                self.skipTest("cargo not installed")
            self.assertNotIn("spec conformance:", out, name)


if __name__ == "__main__":
    unittest.main()

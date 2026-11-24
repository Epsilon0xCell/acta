"""Regression tests for repair round 6 (fifth re-audit findings
W1 to W5, the residue round).

Author: Gavin Blacklock

The fifth re-audit found the two implementations in exact
agreement on every well-formed input and every malformed
policy, with the remaining distance confined to four Python
acceptance residues and one shared agent-shape observation:
a stated null counterparty_id or subtree_root_id read as
absence (W1), a validation door that never examined
witness_policy (W2), a ceiling-curve validator that checked
only the tier fields present (W3), an unknown receipt type
tallied as nothing (W4), and an agent stated as a string
crashing one tree and silently emptying the other (W5).
Each test is named for its finding and encodes the
re-audit's own probes. The differential class at the end
adds the re-audit's five residue cases as permanent cases:
for every one, the Python computation raises and the Rust
conformance runner may not run the case as spec conformance
(its prototype-parameter fallback is non-agreement, as the
re-audits count it).
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from institutio import compute_standing, validate_standing_policy  # noqa: E402
from tests.test_differential import CEILING_CURVE  # noqa: E402
from tests.test_repair_round4 import run_runner_allowing_fail  # noqa: E402
from tests.test_repair_round5 import action, complete_policy  # noqa: E402

TIER_FIELDS = ("min_standing", "max_budget_per_action",
               "max_budget_per_epoch", "max_irreversibility",
               "max_data_sensitivity", "max_delegation_depth",
               "max_fanout")


def valid_policy(**overrides):
    """A complete policy validate_standing_policy accepts:
    burn_unit 50 at multiplier 2 erases the epoch cap of 100
    for both severe codes, satisfying invariant I5."""
    policy = complete_policy()
    policy["scope_classes"]["write"]["burn_unit"] = 50
    policy.update(overrides)
    return policy


class TestW1NullIdentityFields(unittest.TestCase):
    """Finding W1: a stated null counterparty_id or
    subtree_root_id is a validation error, never absence."""

    def test_W1_null_counterparty_id_rejected(self):
        # The re-audit's case N7: the stated null was keyed
        # into diversity accounting as the string form of
        # None and Standing computed 10; Rust rejected at
        # parse. Both receipt level and action level.
        with self.assertRaises(ValueError):
            compute_standing([action(10, counterparty_id=None)],
                             complete_policy(), eval_time=10)
        doc = action(10)
        doc["action"]["counterparty_id"] = None
        with self.assertRaises(ValueError):
            compute_standing([doc], complete_policy(), eval_time=10)

    def test_W1_null_subtree_root_id_rejected(self):
        # Case N8: the stated null fell back to the agent's
        # own subtree through an explicit code path.
        with self.assertRaises(ValueError):
            compute_standing([action(10, subtree_root_id=None)],
                             complete_policy(), eval_time=10)
        doc = action(10)
        doc["action"]["subtree_root_id"] = None
        with self.assertRaises(ValueError):
            compute_standing([doc], complete_policy(), eval_time=10)

    def test_W1_stated_ids_still_compute(self):
        # The strictness is about stated nulls, not stated ids.
        result = compute_standing(
            [action(10, counterparty_id="cp-1",
                    subtree_root_id="agent-1")],
            complete_policy(), eval_time=10)
        self.assertEqual(result["write"]["standing"], 10)


class TestW2WitnessPolicyAtValidation(unittest.TestCase):
    """Finding W2: validate_standing_policy, the function
    charter validation calls, examines witness_policy with
    the same strictness as every other door."""

    def test_W2_validate_rejects_quorum_out_of_bounds(self):
        for bad in ({"witness_key_ids": ["w-1", "w-2"], "quorum": 0},
                    {"witness_key_ids": ["w-1", "w-2"], "quorum": 3},
                    {"witness_key_ids": [], "quorum": 1}):
            errors = validate_standing_policy(
                valid_policy(witness_policy=bad))
            self.assertTrue(
                any("witness_policy" in e for e in errors),
                "%r produced no witness error: %r" % (bad, errors))

    def test_W2_validate_rejects_k_alias_and_bad_forms(self):
        for bad in ({"witness_key_ids": ["w-1", "w-2"], "k": 2},
                    {"witness_key_ids": ["w-1", "w-2"],
                     "quorum": "2"},
                    {"witness_key_ids": ["w-1", "w-2"]},
                    {"witness_key_ids": [7, "w-2"], "quorum": 1},
                    None,
                    ["w-1"]):
            errors = validate_standing_policy(
                valid_policy(witness_policy=bad))
            self.assertTrue(
                any("witness_policy" in e for e in errors),
                "%r produced no witness error: %r" % (bad, errors))

    def test_W2_validate_accepts_spec_form_witness_policy(self):
        errors = validate_standing_policy(valid_policy(
            witness_policy={"witness_key_ids": ["w-1", "w-2"],
                            "quorum": 2}))
        self.assertEqual(errors, [])


class TestW3CurveCompleteness(unittest.TestCase):
    """Finding W3: a tier missing any field is a policy
    error, never a silently incomplete ceilings entry."""

    def test_W3_tier_missing_any_field_rejected(self):
        for field in TIER_FIELDS:
            curve = copy.deepcopy(CEILING_CURVE)
            del curve[0][field]
            policy = complete_policy(ceiling_curve=curve)
            with self.assertRaises(ValueError, msg=field):
                compute_standing([action(10)], policy, eval_time=10)

    def test_W3_complete_curve_still_computes(self):
        result = compute_standing([action(10)], complete_policy(),
                                  eval_time=10)
        self.assertEqual(result["write"]["standing"], 10)
        for field in TIER_FIELDS[1:]:
            self.assertIn(field, result["write"]["ceilings"])


class TestW4UnknownReceiptType(unittest.TestCase):
    """Finding W4: compute_standing raises on an unknown
    receipt type, matching Rust's INVALID_RECEIPT."""

    def test_W4_unknown_receipt_type_rejected(self):
        transfer = action(10)
        transfer["receipt_type"] = "TRANSFER"
        with self.assertRaises(ValueError) as ctx:
            compute_standing([transfer], complete_policy(),
                             eval_time=10)
        self.assertIn("INVALID_RECEIPT", str(ctx.exception))

    def test_W4_known_types_still_tally(self):
        # GRANT and REVOCATION are known types that mint and
        # burn nothing; they remain accepted and inert.
        grant = action(10)
        grant["receipt_type"] = "GRANT"
        result = compute_standing([grant, action(20)],
                                  complete_policy(), eval_time=20)
        self.assertEqual(result["write"]["standing"], 10)


class TestW5AgentShape(unittest.TestCase):
    """Finding W5: an agent that is not the agent object is
    a validation error in both trees, never a crash (Python
    raised AttributeError) and never a silent empty
    computation (Rust)."""

    def test_W5_agent_as_string_is_a_validation_error(self):
        doc = action(10)
        doc["agent"] = "agent-1"
        with self.assertRaises(ValueError):
            compute_standing([doc], complete_policy(), eval_time=10)

    def test_W5_agent_in_other_shapes_is_a_validation_error(self):
        for bad in (7, None, ["agent-1"]):
            doc = action(10)
            doc["agent"] = bad
            with self.assertRaises(ValueError, msg=repr(bad)):
                compute_standing([doc], complete_policy(),
                                 eval_time=10)

    def test_W5_agent_object_and_absent_agent_still_work(self):
        result = compute_standing([action(10)], complete_policy(),
                                  eval_time=10)
        self.assertEqual(result["write"]["standing"], 10)
        doc = action(10)
        del doc["agent"]
        result = compute_standing([doc], complete_policy(),
                                  eval_time=10)
        self.assertEqual(result["write"]["standing"], 10)


def residue_cases():
    """The fifth re-audit's residue cases (its Section 3,
    cases N7, N8, E8, R1, R3): (name, policy, receipts). For
    every one the Python computation raises and the Rust
    runner may not report spec conformance."""
    curve = copy.deepcopy(CEILING_CURVE)
    del curve[0]["max_fanout"]
    transfer = action(10)
    transfer["receipt_type"] = "TRANSFER"
    string_agent = action(10)
    string_agent["agent"] = "agent-1"
    return [
        ("null_counterparty_id", complete_policy(),
         [action(10, counterparty_id=None)]),
        ("null_subtree_root_id", complete_policy(),
         [action(10, subtree_root_id=None)]),
        ("tier_missing_max_fanout",
         complete_policy(ceiling_curve=curve), [action(10)]),
        ("unknown_receipt_type_transfer", complete_policy(),
         [transfer]),
        ("agent_as_string", complete_policy(), [string_agent]),
    ]


class TestRound6DifferentialCases(unittest.TestCase):
    """The fifth re-audit's residue cases, permanent."""

    def test_all_5_cases_reconstructible(self):
        self.assertEqual(len(residue_cases()), 5)

    def test_python_rejects_every_case(self):
        for name, policy, receipts in residue_cases():
            with self.assertRaises(ValueError, msg=name):
                compute_standing(receipts, policy, eval_time=200)

    def test_rust_never_reports_spec_conformance(self):
        for name, policy, receipts in residue_cases():
            document = {
                "name": "round6_%s" % name,
                "kind": "standing",
                "description": "Decision 24 residue case %s: "
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

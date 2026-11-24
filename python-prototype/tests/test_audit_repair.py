"""Regression tests for the 2026-11-23 independent audit repair round.

Author: Gavin Blacklock

Each test is named for the audit finding it closes and encodes the
audit's own attack: it fails on the pre-repair behaviour and passes
on the repaired behaviour.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import (  # noqa: E402
    GENESIS_HASH,
    HmacSigner,
    build_receipt,
    sha256_hex,
    verify_chain,
)
from institutio import (  # noqa: E402
    build_checkpoint,
    compute_standing,
    countersign_outcome,
    example_charter,
    sign_charter,
    validate_charter,
    validate_charter_chain,
    validate_standing_policy,
    verify_checkpoint,
)
from toolgate import ToolGate  # noqa: E402

FOUNDER = HmacSigner(b"unit-test-secret", key_id="founder-root-key-1")
ATTACKER = HmacSigner(b"attacker-secret", key_id="founder-root-key-1")
VERIFIERS = {"founder-root-key-1": FOUNDER}
CP = HmacSigner(b"counterparty-secret", key_id="cp-1")
CP_VERIFIERS = {"cp-1": CP}
# Repair round 3 (finding S3): policies state every field
# Section 16.10 assigns to the policy. GATE_CURVE is the tier set
# the prototype once defaulted to, stated explicitly; CURVE is one
# generous tier for pure computation tests.
HL = 10000000
CURVE = [{"min_standing": 0, "max_budget_per_action": 1000000,
          "max_budget_per_epoch": 10000000, "max_irreversibility": 3,
          "max_data_sensitivity": 3, "max_delegation_depth": 3,
          "max_fanout": 8}]
GATE_CURVE = [
    {"min_standing": 0, "max_budget_per_action": 5,
     "max_budget_per_epoch": 25, "max_irreversibility": 0,
     "max_data_sensitivity": 0, "max_delegation_depth": 0,
     "max_fanout": 0},
    {"min_standing": 1, "max_budget_per_action": 10,
     "max_budget_per_epoch": 50, "max_irreversibility": 0,
     "max_data_sensitivity": 1, "max_delegation_depth": 0,
     "max_fanout": 1},
    {"min_standing": 10, "max_budget_per_action": 50,
     "max_budget_per_epoch": 250, "max_irreversibility": 1,
     "max_data_sensitivity": 2, "max_delegation_depth": 1,
     "max_fanout": 2},
    {"min_standing": 50, "max_budget_per_action": 250,
     "max_budget_per_epoch": 1000, "max_irreversibility": 2,
     "max_data_sensitivity": 3, "max_delegation_depth": 2,
     "max_fanout": 4},
    {"min_standing": 200, "max_budget_per_action": 1000,
     "max_budget_per_epoch": 5000, "max_irreversibility": 3,
     "max_data_sensitivity": 3, "max_delegation_depth": 3,
     "max_fanout": 8},
]
ALL_MULTIPLIERS = {"revoked": 2, "scope": 2, "manifest-mismatch": 1,
                   "budget": 1, "standing-ceiling": 1}
WRITE_HASH = sha256_hex(b"tool-definition:write:v1")
AGENT = {"id": "agent-1", "model": "model-x", "model_version": "1.0"}
CHILD_AGENT = {"id": "agent-2", "model": "model-x", "model_version": "1.0"}


def rich(kind, timestamp, agent_id="agent-1", risk_weight=1,
         reason_code=None, counterparty_sig=None, killed_ids=None):
    receipt = {
        "receipt_type": kind, "timestamp": timestamp,
        "agent": {"id": agent_id},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": risk_weight},
    }
    if reason_code is not None:
        receipt["reason_code"] = reason_code
    if counterparty_sig is not None:
        receipt["counterparty_sig"] = counterparty_sig
        receipt["counterparty_id"] = "cp-1"
    if killed_ids is not None:
        receipt["killed_agent_ids"] = killed_ids
    return receipt


def make_gate(policy=None, expires_at=None):
    gate = ToolGate(
        HmacSigner(b"unit-test-secret", key_id="gate-key-1"),
        standing_policy=policy or {
            "countersign_policy": {"required_for": ["write"]},
            "ceiling_curve": GATE_CURVE,
            "scope_classes": {"write": {
                "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                "half_life_seconds": HL,
                "hop_attenuation_ppm": 1000000,
                "correlated_burn_fraction_ppm": 250000,
                "burn_unit": 5, "burn_multipliers": ALL_MULTIPLIERS}}},
        authorized_key_ids=("founder-root-key-1",),
        counterparty_verifiers=CP_VERIFIERS,
    )
    gate.register_tool("repo.write", WRITE_HASH, scope_class="write",
                       risk_weight=3)
    manifest = {
        "manifest_id": "m-1", "grantor_seat": "founder",
        "grantee_seat": "worker", "agent": AGENT,
        "scope": {"tools": ["repo.write"], "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"spend_units": 1000, "external_calls": 10}},
        "issued_at": 1000,
    }
    if expires_at is not None:
        manifest["expires_at"] = expires_at
    gate.add_delegation(manifest)
    gate.add_delegation({
        "manifest_id": "m-1-child", "grantor_seat": "worker",
        "grantee_seat": "child", "agent": CHILD_AGENT,
        "parent_manifest_id": "m-1",
        "scope": {"tools": ["repo.write"], "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"spend_units": 500, "external_calls": 5}},
        "issued_at": 1000,
    })
    gate.issue_grant("m-1", 1000)
    return gate


def good_sig(gate, agent_id, when):
    """A countersignature over the gate's bound outcome descriptor."""
    arguments_hash = sha256_hex(b"args")
    result_hash = sha256_hex(("result:" + arguments_hash).encode("utf-8"))
    return countersign_outcome(
        CP, agent_id, "repo.write", "write", when,
        risk_weight=3, receipt_id=gate.next_receipt_id(),
        arguments_hash=arguments_hash, result_hash=result_hash)


PINNED_FOUNDER = {"founder-root-key-1"}


class TestC2CharterSignatures(unittest.TestCase):
    def test_C2_unsigned_charter_rejected(self):
        errors = validate_charter(
            example_charter(), verifiers=VERIFIERS,
            pinned_founder_key_ids=PINNED_FOUNDER)
        self.assertTrue(any("not signed" in e for e in errors), errors)

    def test_C2_attacker_signed_charter_rejected(self):
        forged = sign_charter(example_charter(), ATTACKER)
        errors = validate_charter(
            forged, verifiers=VERIFIERS,
            pinned_founder_key_ids=PINNED_FOUNDER)
        self.assertTrue(
            any("signature does not verify" in e for e in errors), errors)

    def test_C2_attacker_signed_amendment_rejected(self):
        founding = sign_charter(example_charter(), FOUNDER)
        amendment_doc = example_charter()
        from institutio import compute_charter_hash
        amendment_doc["predecessor_charter_hash"] = compute_charter_hash(founding)
        amendment_doc["org"]["name"] = "Example Firm Amended"
        forged = sign_charter(amendment_doc, ATTACKER)
        errors = validate_charter_chain(
            [founding, forged], verifiers=VERIFIERS,
            founder_key_ids=PINNED_FOUNDER)
        self.assertTrue(
            any("signature does not verify" in e for e in errors), errors)

    def test_C2_founder_signed_charter_accepted(self):
        signed = sign_charter(example_charter(), FOUNDER)
        self.assertEqual(
            validate_charter(signed, verifiers=VERIFIERS,
                             pinned_founder_key_ids=PINNED_FOUNDER), [])


class TestM1LibraryVerifierRequired(unittest.TestCase):
    def _chain(self, signer):
        receipt = build_receipt(
            signer, "r-1", "ACTION", 0, 1763900000, "seat-founder",
            AGENT, "tools=[read];resources=[repo];ops=[call];limits={}",
            "tool.call", sha256_hex(b"a"), sha256_hex(b"b"), GENESIS_HASH)
        return [receipt]

    def test_M1_verify_chain_without_verifier_fails_closed(self):
        signer = HmacSigner(b"s1", key_id="k1")
        result = verify_chain(self._chain(signer))
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "VERIFIER_REQUIRED")

    def test_M1_second_key_chain_not_accepted_unverified(self):
        attacker = HmacSigner(b"attacker", key_id="k1")
        result = verify_chain(self._chain(attacker),
                              expected_key_id="k1")
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "VERIFIER_REQUIRED")


class TestM2CountersignatureVerification(unittest.TestCase):
    def test_M2_garbage_countersignature_mints_zero(self):
        policy = {"countersign_policy": {"required_for": ["write"]},
                  "scope_classes": {"write": {
                      "mint_rate": 2, "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        receipts = [rich("ACTION", 100, risk_weight=3,
                         counterparty_sig="garbage-string")]
        result = compute_standing(receipts, policy, eval_time=100,
                                  counterparty_verifiers=CP_VERIFIERS)
        self.assertEqual(result["write"]["minted"], 0)

    def test_M2_verified_countersignature_mints_full_weight(self):
        policy = {"countersign_policy": {"required_for": ["write"]},
                  "scope_classes": {"write": {
                      "mint_rate": 2, "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        sig = countersign_outcome(CP, "agent-1", "tool.call", "write", 100,
                                  risk_weight=3)
        receipts = [rich("ACTION", 100, risk_weight=3,
                         counterparty_sig=sig)]
        result = compute_standing(receipts, policy, eval_time=100,
                                  counterparty_verifiers=CP_VERIFIERS)
        self.assertEqual(result["write"]["minted"], 6)

    def test_M2_gate_does_not_record_unverifiable_countersignature(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060, budget_cost=3,
            counterparty_id="cp-1", counterparty_sig="garbage-string")
        self.assertTrue(decision.allowed)
        self.assertNotIn("counterparty_sig", decision.receipt)
        self.assertEqual(
            gate.standing_of("agent-1", 1060)["write"]["standing"], 0)


class TestM3BurnAsymmetry(unittest.TestCase):
    def test_M3_severe_denial_erases_epoch_mint(self):
        # Section 16.10 decision 2 governs (re-audit finding N2):
        # the I5 floor is a policy-validation condition, not a
        # computation-time adjustment. Under a valid policy (epoch
        # mint cap 100, severe burn 5 * 20 = 100 at n = 1), the
        # closed form itself erases the epoch of mint.
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 100,
            "half_life_seconds": HL, "ceiling_curve": CURVE,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 20, "scope": 20}}}}
        self.assertEqual(validate_standing_policy(policy), [])
        receipts = [rich("ACTION", 100 + i) for i in range(100)]
        receipts.append(rich("DENIAL", 500, reason_code="revoked"))
        result = compute_standing(receipts, policy, eval_time=500)
        self.assertEqual(result["write"]["minted"], 100)
        self.assertGreaterEqual(result["write"]["burned"], 100)
        self.assertEqual(result["write"]["standing"], 0)

    def test_M3_policy_without_mint_cap_rejected_by_validation(self):
        # The uncapped policy the pre-amendment computation floored
        # dynamically is now rejected at validation time instead:
        # its epoch of mint is unbounded, so the I5 floor is
        # uncheckable (Section 16.10 decision 2).
        policy = {"scope_classes": {"write": {"mint_rate": 1}}}
        errors = validate_standing_policy(policy)
        self.assertTrue(any("mint_cap_per_epoch" in e for e in errors),
                        errors)

    def test_M3_policy_validation_rejects_weak_severe_burn(self):
        weak = {"scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 100,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 1, "scope": 1}}}}
        errors = validate_standing_policy(weak)
        self.assertTrue(any("I5" in e for e in errors), errors)

    def test_M3_policy_validation_accepts_strong_severe_burn(self):
        strong = {"scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 100,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 20, "scope": 20}}}}
        self.assertEqual(validate_standing_policy(strong), [])


class TestM4KillBurnScope(unittest.TestCase):
    def test_M4_kill_burn_spares_unrelated_seat_firm_wide(self):
        receipts = [
            rich("ACTION", 100, agent_id="rogue", risk_weight=10),
            rich("ACTION", 110, agent_id="sibling", risk_weight=7),
            rich("KILL-BURN", 120, agent_id="rogue",
                 killed_ids=["rogue"]),
        ]
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        result = compute_standing(receipts, policy, eval_time=120)
        self.assertEqual(result["write"]["standing"], 7)
        sibling = compute_standing(receipts, policy, eval_time=120,
                                   agent_id="sibling")
        self.assertEqual(sibling["write"]["standing"], 7)
        rogue = compute_standing(receipts, policy, eval_time=120,
                                 agent_id="rogue")
        self.assertEqual(rogue["write"]["standing"], 0)


class TestM5RecordedScope(unittest.TestCase):
    def test_M5_scope_string_carries_limits(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060, budget_cost=3,
            counterparty_id="cp-1", counterparty_sig=good_sig(gate, "agent-1", 1060))
        self.assertTrue(decision.allowed)
        scope = decision.receipt["scope_granted"]
        self.assertIn("limits={", scope)
        self.assertIn("spend_units=1000", scope)
        self.assertIn("external_calls=10", scope)


class TestM6CharterAmendments(unittest.TestCase):
    def test_M6_frozen_field_amendment_rejected(self):
        from institutio import compute_charter_hash
        founding = sign_charter(example_charter(), FOUNDER)
        amendment_doc = example_charter()
        amendment_doc["predecessor_charter_hash"] = compute_charter_hash(founding)
        amendment_doc["kill_switch"] = {
            "authorized_key_ids": ["attacker-key-9"],
            "recovery_seat": "founder",
        }
        amendment = sign_charter(amendment_doc, FOUNDER)
        errors = validate_charter_chain(
            [founding, amendment], verifiers=VERIFIERS,
            founder_key_ids=PINNED_FOUNDER)
        self.assertTrue(any("frozen field" in e for e in errors), errors)

    def test_M6_missing_standing_policy_rejected(self):
        doc = example_charter()
        del doc["standing_policy"]
        signed = sign_charter(doc, FOUNDER)
        errors = validate_charter(signed, verifiers=VERIFIERS)
        self.assertTrue(
            any("standing_policy" in e for e in errors), errors)

    def test_M6_missing_anchoring_rejected(self):
        doc = example_charter()
        del doc["anchoring"]
        signed = sign_charter(doc, FOUNDER)
        errors = validate_charter(signed, verifiers=VERIFIERS)
        self.assertTrue(any("anchoring" in e for e in errors), errors)


class TestM7GateEnforcementBreadth(unittest.TestCase):
    def test_M7_expired_delegation_denied(self):
        gate = make_gate(expires_at=2000)
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 2060, budget_cost=3,
            counterparty_id="cp-1", counterparty_sig=good_sig(gate, "agent-1", 2060))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scope")

    def test_M7_not_yet_issued_delegation_denied(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 500, budget_cost=3,
            counterparty_id="cp-1", counterparty_sig=good_sig(gate, "agent-1", 500))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scope")

    def test_M7_resource_outside_scope_denied(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060, budget_cost=3,
            resource="prod-database")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scope")

    def test_M7_operation_outside_scope_denied(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060, budget_cost=3,
            operation="delete")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scope")

    def test_M7_epoch_budget_ceiling_denied(self):
        curve = [{"min_standing": 0, "max_budget_per_action": 100,
                  "max_budget_per_epoch": 25, "max_irreversibility": 3,
                  "max_data_sensitivity": 3, "max_delegation_depth": 3,
                  "max_fanout": 8}]
        policy = {"ceiling_curve": curve,
                  "scope_classes": {"write": {
                      "mint_rate": 2, "half_life_seconds": HL,
                      "burn_unit": 5,
                      "burn_multipliers": ALL_MULTIPLIERS}}}
        gate = make_gate(policy=policy)
        first = gate.propose("m-1", "repo.write", WRITE_HASH, "a", 1060,
                             budget_cost=20)
        self.assertTrue(first.allowed)
        second = gate.propose("m-1", "repo.write", WRITE_HASH, "b", 1120,
                              budget_cost=20)
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason_code, "standing-ceiling")

    def test_M7_depth_ceiling_denied_for_child(self):
        gate = make_gate()
        decision = gate.propose(
            "m-1-child", "repo.write", WRITE_HASH, "args", 1060,
            budget_cost=3, counterparty_id="cp-1",
            counterparty_sig=good_sig(gate, "agent-2", 1060))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "standing-ceiling")


class TestM8CheckpointVerification(unittest.TestCase):
    W1 = HmacSigner(b"witness-one-secret", key_id="witness-1")
    W2 = HmacSigner(b"witness-two-secret", key_id="witness-2")
    POLICY = {
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": HL,
            "ceiling_curve": CURVE}},
        # The specification's witness policy form (Section 16.10
        # decision 15): {witness_key_ids, quorum}. This test once
        # wrote a "min_cosigs" field the specification never
        # defined, certifying the wrong field name (finding S5).
        "witness_policy": {"quorum": 2,
                           "witness_key_ids": ["witness-1", "witness-2"]},
    }
    WITNESS_VERIFIERS = {"witness-1": W1, "witness-2": W2}

    def _receipts(self):
        return [rich("ACTION", 100, risk_weight=3),
                rich("ACTION", 110, risk_weight=3)]

    def _checkpoint(self):
        return build_checkpoint(
            self._receipts(), self.POLICY, eval_time=110,
            agent_id="agent-1", org_id="org-1",
            witness_signers=(self.W1, self.W2),
            checkpoint_signer=self.W1)

    def test_M8_checkpoint_verifies(self):
        checkpoint = self._checkpoint()
        errors = verify_checkpoint(
            checkpoint, self._receipts(), self.POLICY,
            witness_verifiers=self.WITNESS_VERIFIERS)
        self.assertEqual(errors, [])

    def test_M8_tampered_checkpoint_rejected(self):
        checkpoint = self._checkpoint()
        forged = copy.deepcopy(checkpoint)
        forged["standing_vector"]["write"] = 9999
        errors = verify_checkpoint(
            forged, self._receipts(), self.POLICY,
            witness_verifiers=self.WITNESS_VERIFIERS)
        self.assertTrue(
            any("does not match recomputation" in e for e in errors),
            errors)

    def test_M8_unwitnessed_checkpoint_rejected_where_quorum_required(self):
        checkpoint = build_checkpoint(
            self._receipts(), self.POLICY, eval_time=110,
            agent_id="agent-1", org_id="org-1")
        errors = verify_checkpoint(
            checkpoint, self._receipts(), self.POLICY,
            witness_verifiers=self.WITNESS_VERIFIERS)
        self.assertTrue(any("quorum" in e for e in errors), errors)

    def test_M8_truncated_chain_rejected(self):
        checkpoint = self._checkpoint()
        errors = verify_checkpoint(
            checkpoint, self._receipts()[:1], self.POLICY,
            witness_verifiers=self.WITNESS_VERIFIERS)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()

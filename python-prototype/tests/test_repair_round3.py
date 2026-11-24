"""Regression tests for repair round 3 (second re-audit findings
S1 to S6 and minors s1 and s5).

Author: Gavin Blacklock

Each test is named for the finding it closes and encodes the
re-audit's own attack: it fails on the pre-repair behaviour and
passes on the repaired behaviour. The theme of the round is
composition: the Python prototype and the Rust implementation are
one definition, so several tests here have twins in the Rust
tree's standing_tests.rs and charter_tests.rs, and the
cross-implementation cases live in test_differential.py.
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import (  # noqa: E402
    GENESIS_HASH,
    HmacSigner,
    build_receipt,
    verify_chain,
)
from institutio import (  # noqa: E402
    COUNTERPARTY_PAYLOAD_TYPE,
    build_checkpoint,
    compute_standing,
    example_charter,
    sign_charter,
    validate_charter,
    validate_standing_policy,
    verify_checkpoint,
)
from institutio.standing import _class_policy, counterparty_outcome_bytes  # noqa: E402

FOUNDER = HmacSigner(b"unit-test-secret", key_id="founder-root-key-1")
VERIFIERS = {"founder-root-key-1": FOUNDER}
W1 = HmacSigner(b"witness-one", key_id="witness-1")
W2 = HmacSigner(b"witness-two", key_id="witness-2")
WITNESS_VERIFIERS = {"witness-1": W1, "witness-2": W2}
# verify_checkpoint looks the checkpoint signer's verifier up in
# the same map it takes witness verifiers from.
ALL_VERIFIERS = {**WITNESS_VERIFIERS, "founder-root-key-1": FOUNDER}
HL = 10000000
CURVE = [{"min_standing": 0, "max_budget_per_action": 1000000,
          "max_budget_per_epoch": 10000000, "max_irreversibility": 3,
          "max_data_sensitivity": 3, "max_delegation_depth": 3,
          "max_fanout": 8}]
AGENT = {"id": "agent-1", "model": "model-x", "model_version": "1.0"}


def rich(kind, timestamp, scope_class="write", risk_weight=1,
         reason_code=None, agent_id="agent-1"):
    doc = {"receipt_type": kind, "timestamp": timestamp,
           "agent": {"id": agent_id},
           "action": {"name": "tool.call", "scope_class": scope_class,
                      "risk_weight": risk_weight}}
    if reason_code is not None:
        doc["reason_code"] = reason_code
    return doc


class TestS1DescriptorBytes(unittest.TestCase):
    def test_S1_descriptor_bytes_are_exactly_the_specified_form(self):
        # Section 16.10 decision 16 fixes the descriptor: canonical
        # JSON of exactly these eight fields, absent fields null.
        payload = counterparty_outcome_bytes(
            "agent-1", "tool.call", "write", 100, risk_weight=3,
            receipt_id="r-1")
        self.assertEqual(
            payload,
            b'{"action_name":"tool.call","agent_id":"agent-1",'
            b'"arguments_hash":null,"receipt_id":"r-1",'
            b'"result_hash":null,"risk_weight":3,'
            b'"scope_class":"write","timestamp":100}')
        self.assertEqual(
            COUNTERPARTY_PAYLOAD_TYPE,
            "application/vnd.acta.counterparty-outcome.v0.1+json")
        self.assertEqual(
            sorted(json.loads(payload)),
            ["action_name", "agent_id", "arguments_hash",
             "receipt_id", "result_hash", "risk_weight",
             "scope_class", "timestamp"])


class TestS3NoInventedDefaults(unittest.TestCase):
    def test_S3_missing_burn_unit_is_an_error_not_a_default(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        receipts = [rich("ACTION", 10),
                    rich("DENIAL", 20, reason_code="budget")]
        with self.assertRaises(ValueError) as ctx:
            compute_standing(receipts, policy, eval_time=20)
        self.assertIn("UNSPECIFIED_BY_SPEC", str(ctx.exception))
        self.assertIn("burn_unit", str(ctx.exception))

    def test_S3_missing_mint_rate_is_an_error_not_a_default(self):
        policy = {"scope_classes": {"write": {
            "half_life_seconds": HL, "ceiling_curve": CURVE}}}
        with self.assertRaises(ValueError) as ctx:
            compute_standing([rich("ACTION", 10)], policy, eval_time=10)
        self.assertIn("mint_rate", str(ctx.exception))

    def test_S3_missing_ceiling_curve_is_an_error_not_a_default(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL}}}
        with self.assertRaises(ValueError) as ctx:
            compute_standing([rich("ACTION", 10)], policy, eval_time=10)
        self.assertIn("ceiling_curve", str(ctx.exception))

    def test_S3_missing_half_life_is_an_error_not_a_default(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "ceiling_curve": CURVE}}}
        with self.assertRaises(ValueError) as ctx:
            compute_standing([rich("ACTION", 10)], policy, eval_time=10)
        self.assertIn("half_life_seconds", str(ctx.exception))


class TestS4OneKillFieldName(unittest.TestCase):
    def test_S4_gate_kill_receipt_uses_killed_agent_ids_only(self):
        from tests.test_toolgate import POLICY, make_gate, FOUNDER as TG_FOUNDER
        gate = make_gate()
        gate.kill_burn("m-1", 2060, TG_FOUNDER)
        kill = gate.chain[-1]
        self.assertIn("agent-2", kill["killed_agent_ids"])
        self.assertNotIn("kill_subtree_agent_ids", json.dumps(kill))
        entry = gate.standing_of("agent-2", 2060)
        self.assertEqual(entry.get("write", {}).get("standing", 0), 0)


class TestS5SpecFormWitnessQuorum(unittest.TestCase):
    POLICY = {
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": HL,
            "ceiling_curve": CURVE}},
        "witness_policy": {"witness_key_ids": ["witness-1", "witness-2"],
                           "quorum": 2},
    }
    RECEIPTS = None

    def _checkpoint(self, witnesses):
        return build_checkpoint(
            [rich("ACTION", 10)], self.POLICY, eval_time=10,
            agent_id="agent-1", org_id="org-1", charter_hash="c" * 64,
            witness_signers=tuple(witnesses),
            checkpoint_signer=FOUNDER)

    def test_S5_quorum_two_unmet_by_one_witness(self):
        checkpoint = self._checkpoint([W1])
        errors = verify_checkpoint(
            checkpoint, [rich("ACTION", 10)], self.POLICY,
            witness_verifiers=ALL_VERIFIERS)
        self.assertTrue(any("quorum" in e for e in errors), errors)

    def test_S5_quorum_two_met_by_two_witnesses(self):
        checkpoint = self._checkpoint([W1, W2])
        errors = verify_checkpoint(
            checkpoint, [rich("ACTION", 10)], self.POLICY,
            witness_verifiers=ALL_VERIFIERS)
        self.assertEqual(errors, [], errors)

    def test_S5_min_cosigs_field_buys_nothing(self):
        # A policy stating the field the specification never
        # defined buys nothing, and since repair round 4 (third
        # re-audit minor t6) it buys less than nothing: a witness
        # policy carrying any key besides witness_key_ids and
        # quorum is malformed under decision 15 and is rejected as
        # such, where round 3 merely ignored the phantom field.
        policy = copy.deepcopy(self.POLICY)
        policy["witness_policy"] = {
            "witness_key_ids": ["witness-1", "witness-2"],
            "min_cosigs": 2}
        # Repair round 5 premise change (finding S5 residue,
        # Section 16.10 decision 24 row (e)): a malformed
        # witness policy is now an error at computation entry,
        # so a checkpoint can no longer be built under one.
        # The checkpoint is built under the spec-form policy
        # and the malformed policy is presented at verification,
        # where this test's assertion has always lived.
        checkpoint = build_checkpoint(
            [rich("ACTION", 10)], self.POLICY, eval_time=10,
            agent_id="agent-1", org_id="org-1", charter_hash="c" * 64,
            checkpoint_signer=FOUNDER)
        errors = verify_checkpoint(
            checkpoint, [rich("ACTION", 10)], policy,
            witness_verifiers=WITNESS_VERIFIERS)
        self.assertTrue(any("witness_policy" in e for e in errors),
                        errors)


class TestS6DuplicateReceiptIds(unittest.TestCase):
    def _receipt(self, signer, receipt_id, sequence, prior):
        return build_receipt(
            signer, receipt_id, "ACTION", sequence, 1000 + sequence,
            "founder", AGENT, {"tools": ["repo.write"]}, "repo.write",
            "a" * 64, "b" * 64, prior)

    def test_S6_verify_chain_rejects_duplicate_receipt_id(self):
        first = self._receipt(FOUNDER, "dup-1", 0, GENESIS_HASH)
        second = self._receipt(
            FOUNDER, "dup-1", 1, first["receipt_hash"])
        result = verify_chain([first, second], verifier=FOUNDER)
        self.assertFalse(result.ok, result)
        self.assertEqual(result.failure_code, "DUPLICATE_RECEIPT_ID",
                         result)

    def test_S6_compute_standing_rejects_duplicate_receipt_id(self):
        one = rich("ACTION", 10)
        one["receipt_id"] = "dup-1"
        two = rich("ACTION", 20)
        two["receipt_id"] = "dup-1"
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        with self.assertRaises(ValueError):
            compute_standing([one, two], policy, eval_time=20)


class TestMinorsRound3(unittest.TestCase):
    def test_s1_dotted_frozen_field_is_a_validation_error(self):
        charter = example_charter()
        charter["amendment"]["frozen_fields"] = [
            "kill_switch.authorized_key_ids"]
        signed = sign_charter(charter, FOUNDER)
        errors = validate_charter(
            signed, verifiers=VERIFIERS,
            pinned_founder_key_ids={"founder-root-key-1"})
        self.assertTrue(any("frozen_fields" in e for e in errors),
                        errors)

    def test_s1_unknown_frozen_field_is_a_validation_error(self):
        charter = example_charter()
        charter["amendment"]["frozen_fields"] = ["no_such_field"]
        signed = sign_charter(charter, FOUNDER)
        errors = validate_charter(
            signed, verifiers=VERIFIERS,
            pinned_founder_key_ids={"founder-root-key-1"})
        self.assertTrue(any("frozen_fields" in e for e in errors),
                        errors)

    def test_s5_epoch_seconds_zero_is_an_error(self):
        policy = {"epoch_seconds": 0,
                  "scope_classes": {"write": {
                      "mint_rate": 1, "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        with self.assertRaises(ValueError):
            compute_standing([rich("ACTION", 10)], policy, eval_time=10)
        self.assertTrue(any(
            "epoch_seconds" in e
            for e in validate_standing_policy(policy)))

    def test_diversity_caps_per_class_placement_is_an_error(self):
        # Section 16.10 decision 18: caps live at policy level.
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "diversity_caps": {
                "per_counterparty_fraction_ppm": 500000}}}}
        with self.assertRaises(ValueError) as ctx:
            _class_policy(policy, "write")
        self.assertIn("decision 18", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

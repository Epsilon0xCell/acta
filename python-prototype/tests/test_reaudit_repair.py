"""Repair Round 2 regression tests, one per re-audit finding.

Each test is named for the finding it closes and fails on the
pre-repair behaviour: REAUDIT-2026-11-23.md residuals of C2, M2,
M6, M7, M8, majors N2, and minors r1, r3, r4, r5, r6, r9, r10.

Author: Gavin Blacklock
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
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
    compute_charter_hash,
    compute_standing,
    countersign_outcome,
    example_charter,
    sign_charter,
    validate_charter,
    validate_charter_chain,
    verify_checkpoint,
)
from toolgate import ToolGate, sign_delegation  # noqa: E402

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(CODE_DIR, "verifier", "verify.py")
FIXTURES = os.path.join(CODE_DIR, "fixtures")
SECRET_FILE = os.path.join(FIXTURES, "test_secret.txt")

FOUNDER = HmacSigner(b"founder-secret", key_id="founder-root-key-1")
ATTACKER = HmacSigner(b"attacker-secret", key_id="attacker-key-1")
CP = HmacSigner(b"counterparty-secret", key_id="cp-1")
VERIFIERS = {"founder-root-key-1": FOUNDER, "attacker-key-1": ATTACKER}
PINNED = {"founder-root-key-1"}
AGENT = {"id": "agent-1", "model": "model-x", "model_version": "1.0"}
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
WRITE_HASH = sha256_hex(b"definition:write")
READ_HASH = sha256_hex(b"definition:read")


def rich(kind, timestamp, scope_class="write", risk_weight=1,
         counterparty_sig=None, counterparty_id="cp-1",
         reason_code=None, agent_id="agent-1", depth=0,
         receipt_id=None, arguments_hash=None, result_hash=None):
    action = {"name": "tool.call", "scope_class": scope_class,
              "risk_weight": risk_weight, "delegation_depth": depth}
    if arguments_hash is not None:
        action["arguments_hash"] = arguments_hash
    receipt = {"receipt_type": kind, "timestamp": timestamp,
               "agent": {"id": agent_id}, "action": action}
    if receipt_id is not None:
        receipt["receipt_id"] = receipt_id
    if result_hash is not None:
        receipt["result_hash"] = result_hash
    if counterparty_sig is not None:
        receipt["counterparty_sig"] = counterparty_sig
        receipt["counterparty_id"] = counterparty_id
    if reason_code is not None:
        receipt["reason_code"] = reason_code
    return receipt


class TestC2TrustAnchor(unittest.TestCase):
    def test_C2_self_declared_anchor_rejected(self):
        # The charter declares the attacker's key as its founder
        # key and its amendment authority. The caller's pinned set
        # names the real founder key, so the charter's own
        # declarations must not become the trust anchor.
        charter = example_charter()
        charter["org"]["founder_key_id"] = "attacker-key-1"
        charter["amendment"]["authorized_key_ids"] = ["attacker-key-1"]
        forged = sign_charter(charter, ATTACKER)
        errors = validate_charter(forged, verifiers=VERIFIERS,
                                  pinned_founder_key_ids=PINNED)
        # Rejected against the caller's pinned founder key, not
        # accepted under the charter's self-declared attacker key.
        self.assertTrue(any("does not verify" in e for e in errors),
                        errors)

    def test_C2_empty_predecessor_authorises_no_amendment(self):
        founding_doc = example_charter()
        founding_doc["amendment"]["authorized_key_ids"] = []
        founding = sign_charter(founding_doc, FOUNDER)
        amendment_doc = example_charter()
        amendment_doc["predecessor_charter_hash"] = (
            compute_charter_hash(founding))
        amendment_doc["org"]["name"] = "Example Firm Amended"
        amendment = sign_charter(amendment_doc, FOUNDER)
        errors = validate_charter_chain(
            [founding, amendment], verifiers=VERIFIERS,
            founder_key_ids=PINNED)
        self.assertTrue(any("authorised key set for this charter "
                            "is empty" in e for e in errors), errors)


class TestM2BoundCountersignature(unittest.TestCase):
    POLICY = {"countersign_policy": {"required_for": ["write"]},
              "ceiling_curve": GATE_CURVE,
              "scope_classes": {
                  "write": {
                      "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                      "half_life_seconds": HL,
                      "hop_attenuation_ppm": 1000000,
                      "burn_unit": 5,
                      "burn_multipliers": ALL_MULTIPLIERS},
                  # The gate registers its tools in class "default";
                  # stated explicitly (finding S3) rather than left
                  # to a prototype default.
                  "default": {
                      "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                      "half_life_seconds": HL,
                      "hop_attenuation_ppm": 1000000,
                      "burn_unit": 5,
                      "burn_multipliers": ALL_MULTIPLIERS}}}
    VER = {"cp-1": CP}

    def test_M2_countersignature_replay_across_receipts_mints_once(self):
        ah1, rh1 = sha256_hex(b"args-1"), sha256_hex(b"result-1")
        ah2, rh2 = sha256_hex(b"args-2"), sha256_hex(b"result-2")
        sig = countersign_outcome(
            CP, "agent-1", "tool.call", "write", 100, risk_weight=3,
            receipt_id="r-0001", arguments_hash=ah1, result_hash=rh1)
        genuine = rich("ACTION", 100, risk_weight=3,
                       counterparty_sig=sig, receipt_id="r-0001",
                       arguments_hash=ah1, result_hash=rh1)
        replayed = rich("ACTION", 100, risk_weight=3,
                        counterparty_sig=sig, receipt_id="r-0002",
                        arguments_hash=ah2, result_hash=rh2)
        result = compute_standing(
            [genuine, replayed], self.POLICY, eval_time=100,
            counterparty_verifiers=self.VER)
        self.assertEqual(result["write"]["minted"], 6)
        self.assertEqual(result["write"]["standing"], 6)

    def test_M2_countersignature_reweighting_mints_zero(self):
        ah, rh = sha256_hex(b"args"), sha256_hex(b"result")
        sig = countersign_outcome(
            CP, "agent-1", "tool.call", "write", 100, risk_weight=1,
            receipt_id="r-0001", arguments_hash=ah, result_hash=rh)
        inflated = rich("ACTION", 100, risk_weight=100,
                        counterparty_sig=sig, receipt_id="r-0001",
                        arguments_hash=ah, result_hash=rh)
        result = compute_standing(
            [inflated], self.POLICY, eval_time=100,
            counterparty_verifiers=self.VER)
        self.assertEqual(result["write"]["minted"], 0)
        self.assertEqual(result["write"]["standing"], 0)


class TestM6FrozenFieldsFrozen(unittest.TestCase):
    def _founding(self):
        return sign_charter(example_charter(), FOUNDER)

    def _amendment(self, mutate):
        doc = example_charter()
        doc["predecessor_charter_hash"] = compute_charter_hash(
            self._founding())
        mutate(doc)
        return sign_charter(doc, FOUNDER)

    def test_M6_two_step_unfreeze_rejected_at_step_1(self):
        def unfreeze(doc):
            doc["frozen_fields"] = []
            doc["kill_switch"]["description"] = "rewritten kill switch"
        step1 = self._amendment(unfreeze)
        errors = validate_charter_chain(
            [self._founding(), step1], verifiers=VERIFIERS,
            founder_key_ids=PINNED)
        self.assertTrue(any("frozen" in e for e in errors), errors)

    def test_M6_frozen_fields_may_only_grow(self):
        def grow(doc):
            doc["frozen_fields"] = ["kill_switch", "standing_policy"]
            doc["org"]["name"] = "Example Firm Amended"
        amendment = self._amendment(grow)
        errors = validate_charter_chain(
            [self._founding(), amendment], verifiers=VERIFIERS,
            founder_key_ids=PINNED)
        self.assertEqual(errors, [], errors)


def make_gate(policy=None, **gate_kwargs):
    gate = ToolGate(
        HmacSigner(b"unit-test-secret", key_id="gate-key-1"),
        standing_policy=policy or {
            "countersign_policy": {"required_for": ["write", "default"]},
            "ceiling_curve": GATE_CURVE,
            "scope_classes": {
                "write": {
                    "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                    "half_life_seconds": HL,
                    "hop_attenuation_ppm": 1000000,
                    "correlated_burn_fraction_ppm": 250000,
                    "burn_unit": 5,
                    "burn_multipliers": ALL_MULTIPLIERS},
                "default": {
                    "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                    "half_life_seconds": HL,
                    "hop_attenuation_ppm": 1000000,
                    "correlated_burn_fraction_ppm": 250000,
                    "burn_unit": 5,
                    "burn_multipliers": ALL_MULTIPLIERS}}},
        authorized_key_ids={"gate-key-1"},
        counterparty_verifiers={"cp-1": CP},
        **gate_kwargs)
    gate.register_tool("repo.write", WRITE_HASH, risk_weight=3)
    gate.register_tool("repo.read", READ_HASH, risk_weight=1)
    return gate


def manifest(manifest_id, agent, scope, parent=None, seat=None):
    doc = {
        "manifest_id": manifest_id,
        "grantor_seat": "seat-root",
        "grantee_seat": seat or ("seat-%s" % agent["id"]),
        "agent": agent,
        "scope": scope,
    }
    if parent:
        doc["parent_manifest_id"] = parent
    return doc


def bound_sig(gate, agent_id, when, tool="repo.write", risk_weight=3,
              arguments="args"):
    arguments_hash = sha256_hex(arguments.encode("utf-8"))
    result_hash = sha256_hex(("result:" + arguments_hash).encode("utf-8"))
    return countersign_outcome(
        CP, agent_id, tool, "write", when, risk_weight=risk_weight,
        receipt_id=gate.next_receipt_id(),
        arguments_hash=arguments_hash, result_hash=result_hash)


FULL_SCOPE = {
    "tools": ["repo.write", "repo.read"],
    "resources": ["repo"],
    "operations": ["call"],
    "limits": {"spend_units": 1000, "external_calls": 100},
}


class TestM7GateResiduals(unittest.TestCase):
    def test_M7_external_calls_limit_denied(self):
        gate = make_gate()
        scope = copy.deepcopy(FULL_SCOPE)
        scope["limits"]["external_calls"] = 1
        gate.add_delegation(manifest("m-1", AGENT, scope))
        first = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060,
            budget_cost=3, counterparty_id="cp-1",
            counterparty_sig=bound_sig(gate, "agent-1", 1060))
        self.assertTrue(first.allowed, first.reason_code)
        second = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1120,
            budget_cost=3, counterparty_id="cp-1",
            counterparty_sig=bound_sig(gate, "agent-1", 1120))
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason_code, "budget")
        self.assertIn("external_calls",
                      second.receipt["verdict"]["detail"])

    def test_M7_signed_delegation_verified_and_forgery_rejected(self):
        signer = HmacSigner(b"delegation-secret",
                            key_id="delegation-key-1")
        gate = make_gate(
            delegation_verifiers={"delegation-key-1": signer},
            require_signed_delegations=True)
        good = sign_delegation(
            signer, manifest("m-1", AGENT, copy.deepcopy(FULL_SCOPE)))
        gate.add_delegation(good)
        forged = sign_delegation(
            signer, manifest("m-2", AGENT, copy.deepcopy(FULL_SCOPE)))
        forged["scope"]["limits"]["spend_units"] = 999999
        with self.assertRaises(ValueError):
            gate.add_delegation(forged)
        with self.assertRaises(ValueError):
            gate.add_delegation(
                manifest("m-3", AGENT, copy.deepcopy(FULL_SCOPE)))


class TestM8CheckpointIdentityBinding(unittest.TestCase):
    POLICY = {"scope_classes": {"write": {
        "mint_rate": 2, "half_life_seconds": HL,
        "ceiling_curve": CURVE}}}

    def _chain(self):
        signer = HmacSigner(b"unit-test-secret", key_id="acta-test-key-1")
        receipts = []
        prior = GENESIS_HASH
        for i in range(2):
            receipt = build_receipt(
                signer, "r-%04d" % (i + 1), "ACTION", i, 100 + 60 * i,
                "seat-founder", AGENT, "tools=[repo.write]",
                "tool.call", sha256_hex(b"args-%d" % i),
                sha256_hex(b"result-%d" % i), prior,
                action_extra={"scope_class": "write", "risk_weight": 1})
            receipts.append(receipt)
            prior = receipt["receipt_hash"]
        return receipts

    def test_M8_unwitnessed_identity_tamper_rejected(self):
        receipts = self._chain()
        checkpoint = build_checkpoint(
            receipts, self.POLICY, eval_time=200, agent_id="agent-1",
            org_id="org-x", charter_hash="ab" * 32)
        self.assertEqual(
            verify_checkpoint(checkpoint, receipts, self.POLICY), [])
        for field, forged in (
            ("charter_hash", "cd" * 32),
            ("org_id", "org-forged"),
            ("eval_time", 201),
        ):
            tampered = copy.deepcopy(checkpoint)
            tampered[field] = forged
            errors = verify_checkpoint(tampered, receipts, self.POLICY)
            self.assertTrue(errors, (field, errors))


class TestN2SpecExactBurn(unittest.TestCase):
    def test_N2_burn_closed_form_quadratic(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 100, "half_life_seconds": HL,
            "burn_unit": 5, "burn_multipliers": {"budget": 1},
            "ceiling_curve": CURVE}}}
        receipts = [rich("ACTION", 10)]
        receipts.append(rich("DENIAL", 20, reason_code="budget"))
        receipts.append(rich("DENIAL", 30, reason_code="budget"))
        result = compute_standing(receipts, policy, eval_time=30)
        # burn_unit 5, multiplier 1: 5 * 1^2 + 5 * 2^2 = 25.
        self.assertEqual(result["write"]["burned"], 25)
        self.assertEqual(result["write"]["standing"], 75)

    def test_N2_hop_attenuation_ppm(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "hop_attenuation_ppm": 500000,
            "half_life_seconds": HL, "ceiling_curve": CURVE}}}
        receipts = [rich("ACTION", 10, risk_weight=8, depth=1)]
        result = compute_standing(receipts, policy, eval_time=10)
        self.assertEqual(result["write"]["minted"], 4)

    def test_N2_correlated_burn_fraction_ppm(self):
        policy = {
            "scope_classes": {
                "write": {"mint_rate": 1, "burn_unit": 40,
                          "burn_multipliers": {"revoked": 1},
                          "correlated_burn_fraction_ppm": 250000,
                          "half_life_seconds": HL,
                          "ceiling_curve": CURVE},
                "read": {"mint_rate": 1, "half_life_seconds": HL,
                         "ceiling_curve": CURVE},
            },
        }
        receipts = [
            rich("ACTION", 10, scope_class="write", risk_weight=100),
            rich("ACTION", 11, scope_class="read", risk_weight=10),
            rich("DENIAL", 20, scope_class="write",
                 reason_code="revoked"),
        ]
        result = compute_standing(receipts, policy, eval_time=20)
        # Severe burn 40 in write; correlated burn floor(40 / 4) = 10
        # erases the read class mint of 10.
        self.assertEqual(result["write"]["standing"], 60)
        self.assertEqual(result["read"]["burned"], 10)
        self.assertEqual(result["read"]["standing"], 0)

    def test_N2_diversity_caps_fraction_object(self):
        # Section 16.10 decision 18 (repair round 3): diversity
        # caps live at standing_policy level. This test once wrote
        # them inside the scope class, a placement only one
        # implementation honoured; the per-class form is now an
        # explicit error (see test_repair_round3).
        policy = {"diversity_caps": {
                      "per_counterparty_fraction_ppm": 500000},
                  "scope_classes": {"write": {
                      "mint_rate": 1, "mint_cap_per_epoch": 100,
                      "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        receipts = [rich("ACTION", 10 + i, risk_weight=30)
                    for i in range(3)]
        result = compute_standing(receipts, policy, eval_time=20)
        # One counterparty may mint at most half the epoch cap.
        self.assertEqual(result["write"]["minted"], 50)


class TestMinors(unittest.TestCase):
    def test_r1_standalone_verifier_requires_receipt_version(self):
        with open(os.path.join(FIXTURES, "fixture_01_valid_chain.json"),
                  encoding="utf-8") as handle:
            fixture = json.load(handle)
        bundle = copy.deepcopy(fixture["bundle"])
        del bundle["receipts"][0]["receipt_version"]
        handle_fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle_fd, "w", encoding="utf-8") as out:
            json.dump(bundle, out)
        result = subprocess.run(
            [sys.executable, VERIFIER, path,
             "--secret-file", SECRET_FILE,
             "--key-id", "acta-test-key-1"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("INVALID_RECEIPT", result.stdout)
        self.assertIn("receipt_version", result.stdout)

    def test_r3_string_risk_weight_rejected(self):
        bad = rich("ACTION", 10)
        bad["action"]["risk_weight"] = "3"
        with self.assertRaises(ValueError):
            compute_standing([bad], {}, eval_time=10)

    def test_r3_negative_depth_rejected(self):
        bad = rich("ACTION", 10, depth=-1)
        with self.assertRaises(ValueError):
            compute_standing([bad], {}, eval_time=10)

    def test_r4_envelope_key_id_must_match_verifier(self):
        signer = HmacSigner(b"unit-test-secret", key_id="real-key-1")
        receipt = build_receipt(
            signer, "r-0001", "ACTION", 0, 100, "seat-founder", AGENT,
            "tools=[repo.write]", "tool.call", sha256_hex(b"args"),
            sha256_hex(b"result"), GENESIS_HASH)
        self.assertTrue(verify_chain([receipt], verifier=signer).ok)
        relabelled = copy.deepcopy(receipt)
        relabelled["envelope"]["signatures"][0]["key_id"] = "other-key"
        result = verify_chain([relabelled], verifier=signer)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "KEY_ID_MISMATCH")

    def test_r5_empty_chain_rejected(self):
        signer = HmacSigner(b"unit-test-secret", key_id="real-key-1")
        result = verify_chain([], verifier=signer)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "EMPTY_CHAIN")
        handle_fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle_fd, "w", encoding="utf-8") as out:
            json.dump({"receipts": []}, out)
        proc = subprocess.run(
            [sys.executable, VERIFIER, path,
             "--secret-file", SECRET_FILE,
             "--key-id", "acta-test-key-1"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("EMPTY_CHAIN", proc.stdout)

    def test_r6_unknown_scope_dimension_rejected(self):
        from institutio.charter import scope_subset_errors
        parent = {"tools": ["a"], "limits": {"spend_units": 10}}
        child = {"tools": ["a"], "seats": ["seat-1"]}
        errors = scope_subset_errors(child, parent, "child scope")
        self.assertTrue(any("unknown scope dimension" in e
                            for e in errors), errors)

    def test_r6_boolean_limit_rejected(self):
        from institutio.charter import scope_subset_errors
        parent = {"limits": {"spend_units": True}}
        child = {"limits": {"spend_units": 1}}
        errors = scope_subset_errors(child, parent, "child scope")
        self.assertTrue(
            any("boolean" in e or "non-negative integer" in e
                for e in errors), errors)

    def test_r9_correlated_burn_reaches_later_class(self):
        policy = {
            "scope_classes": {
                "write": {"mint_rate": 1, "burn_unit": 40,
                          "burn_multipliers": {"revoked": 1},
                          "correlated_burn_fraction_ppm": 250000,
                          "half_life_seconds": HL,
                          "ceiling_curve": CURVE},
                "read": {"mint_rate": 1, "half_life_seconds": HL,
                         "ceiling_curve": CURVE},
            },
        }
        receipts = [
            rich("ACTION", 10, scope_class="write", risk_weight=100),
            rich("DENIAL", 20, scope_class="write",
                 reason_code="revoked"),
            rich("ACTION", 30, scope_class="read", risk_weight=10),
        ]
        result = compute_standing(receipts, policy, eval_time=30)
        # Decision 7: correlated classes are every other class with
        # a receipt in the segment, including one first touched
        # after the denial: floor(40 / 4) = 10 erases its mint.
        self.assertEqual(result["read"]["burned"], 10)
        self.assertEqual(result["read"]["standing"], 0)

    def test_r10_gate_records_no_unverified_countersignature(self):
        gate = ToolGate(
            HmacSigner(b"unit-test-secret", key_id="gate-key-1"),
            standing_policy={
                "countersign_policy": {"required_for": ["write", "default"]},
                "ceiling_curve": GATE_CURVE,
                "scope_classes": {
                    "write": {
                        "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                        "half_life_seconds": HL,
                        "hop_attenuation_ppm": 1000000,
                        "correlated_burn_fraction_ppm": 250000,
                        "burn_unit": 5,
                        "burn_multipliers": ALL_MULTIPLIERS},
                    "default": {
                        "mint_rate": 2, "mint_cap_per_epoch": 1000000,
                        "half_life_seconds": HL,
                        "hop_attenuation_ppm": 1000000,
                        "burn_unit": 5,
                        "burn_multipliers": ALL_MULTIPLIERS}}},
            authorized_key_ids={"gate-key-1"})
        gate.register_tool("repo.write", WRITE_HASH, risk_weight=3)
        gate.add_delegation(manifest(
            "m-1", AGENT, copy.deepcopy(FULL_SCOPE)))
        decision = gate.propose(
            "m-1", "repo.write", WRITE_HASH, "args", 1060,
            budget_cost=3, counterparty_id="cp-1",
            counterparty_sig="sig:deadbeef")
        self.assertTrue(decision.allowed, decision.reason_code)
        action_receipt = gate.chain[-1]
        self.assertNotIn("counterparty_sig", action_receipt)


if __name__ == "__main__":
    unittest.main()

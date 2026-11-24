"""Cross-implementation differential test (re-audit finding N2).

One generated chain and one Section 16.10-complete policy are run
through the Python ComputeStanding and through the Rust
institutio-core conformance runner. Both must produce identical
Standing vectors. The chain exercises the paths the re-audit found
divergent: the quadratic burn closed form, hop_attenuation_ppm,
correlated_burn_fraction_ppm (including a class first touched
after the severe denial, decision 7), and diversity fraction caps
that bind.

The expected values below were computed by hand from Section
16.10, not copied from either implementation:

write (mint_rate 2, cap 40, hop 500000 ppm, burn_unit 2,
multipliers revoked 2 / budget 1, counterparty fraction cap
250000 ppm = 10 per epoch):
  t=10  ACTION risk 3 depth 0 cp-a: mint 6        (cp-a epoch 0: 6)
  t=20  ACTION risk 3 depth 1 cp-a: 6 halved = 3  (cp-a epoch 0: 9)
  t=30  ACTION risk 5 depth 0 cp-b: mint 10       (cp-b epoch 0: 10)
  t=40  DENIAL budget, n=1: burn 2 * 1 * 1 = 2
  t=50  ACTION risk 5 depth 0 cp-a: 10 clipped by the cp-a cap
        to 1                                       (cp-a epoch 0: 10)
  t=150 ACTION risk 5 depth 0 cp-a: mint 10        (epoch 1)
  t=160 DENIAL revoked, n=2, severe: burn 2 * 2 * 4 = 16,
        correlated burn floor(16 / 4) = 4 into read
  t=180 BURN burn_amount 7: recorded only
  write totals: actions 5, denials 2, minted 30, burned 18,
  burn_recorded 7, standing 12
read (mint_rate 1, cap 40):
  t=170 ACTION risk 10 cp-a: mint 10, correlated burned 4
  read totals: actions 1, denials 0, minted 10, burned 4,
  standing 6
An agent-2 write action at t=15 proves per-agent separation in
both implementations (the fixture computes agent-1 only).

Repair round 3 extends this file with the composition cases the
second re-audit named as its structural blind spots (observation
o4): a countersigned chain the Rust side verifies under a real
key map (finding S1, with cross-verification in both directions),
a subtree kill under the one field name (finding S4), and an
incomplete policy that errors in both trees (finding S3).

Author: Gavin Blacklock
"""

import base64
import binascii
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import Ed25519Signer, sha256_hex  # noqa: E402
from institutio import compute_standing, countersign_outcome  # noqa: E402

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_DIR = os.path.join(os.path.dirname(CODE_DIR), "code-rust")
SECRET_FILE = os.path.join(CODE_DIR, "fixtures", "test_secret.txt")

MULTIPLIERS = {"revoked": 2, "scope": 2, "manifest-mismatch": 1,
               "budget": 1, "standing-ceiling": 1}
CEILING_CURVE = [
    {"min_standing": 0, "max_budget_per_action": 5,
     "max_budget_per_epoch": 25, "max_irreversibility": 0,
     "max_data_sensitivity": 0, "max_delegation_depth": 0,
     "max_fanout": 0},
    {"min_standing": 10, "max_budget_per_action": 50,
     "max_budget_per_epoch": 250, "max_irreversibility": 1,
     "max_data_sensitivity": 2, "max_delegation_depth": 1,
     "max_fanout": 2},
]
POLICY = {
    "epoch_seconds": 100,
    "ceiling_curve": CEILING_CURVE,
    # diversity_caps sits at policy level: the encoding home the
    # Rust policy parser reads, which the Python parser also
    # honours (its class merge inherits top-level keys). The
    # read class is unaffected: its single mint of 10 is exactly
    # at, not over, its counterparty cap of 10.
    "diversity_caps": {
        "per_counterparty_fraction_ppm": 250000,
        "per_task_type_fraction_ppm": 750000},
    "scope_classes": {
        "write": {
            "mint_rate": 2, "mint_cap_per_epoch": 40,
            "half_life_seconds": 1000, "hop_attenuation_ppm": 500000,
            "burn_unit": 2, "burn_multipliers": MULTIPLIERS,
            "severe_reason_codes": ["revoked", "scope"],
            "correlated_burn_fraction_ppm": 250000,
        },
        "read": {
            "mint_rate": 1, "mint_cap_per_epoch": 40,
            "half_life_seconds": 1000, "hop_attenuation_ppm": 1000000,
            "burn_unit": 2, "burn_multipliers": MULTIPLIERS,
            "severe_reason_codes": ["revoked", "scope"],
            "correlated_burn_fraction_ppm": 250000,
        },
    },
}
EXPECTED = {
    "write": {"standing": 12, "minted": 30, "burned": 18,
              "burn_recorded": 7, "actions": 5, "denials": 2},
    "read": {"standing": 6, "minted": 10, "burned": 4,
             "burn_recorded": 0, "actions": 1, "denials": 0},
}


def receipt(kind, timestamp, scope_class="write", risk_weight=1,
            depth=0, counterparty_id=None, reason_code=None,
            agent_id="agent-1", burn_amount=None):
    action = {"name": "tool.call", "scope_class": scope_class,
              "risk_weight": risk_weight, "delegation_depth": depth}
    doc = {"receipt_type": kind, "timestamp": timestamp,
           "agent": {"id": agent_id}, "action": action}
    if counterparty_id is not None:
        doc["counterparty_id"] = counterparty_id
    if reason_code is not None:
        doc["reason_code"] = reason_code
    if burn_amount is not None:
        doc["burn_amount"] = burn_amount
    return doc


def chain():
    return [
        receipt("ACTION", 10, risk_weight=3, counterparty_id="cp-a"),
        receipt("ACTION", 15, risk_weight=2, counterparty_id="cp-a",
                agent_id="agent-2"),
        receipt("ACTION", 20, risk_weight=3, depth=1,
                counterparty_id="cp-a"),
        receipt("ACTION", 30, risk_weight=5, counterparty_id="cp-b"),
        receipt("DENIAL", 40, reason_code="budget"),
        receipt("ACTION", 50, risk_weight=5, counterparty_id="cp-a"),
        receipt("ACTION", 150, risk_weight=5, counterparty_id="cp-a"),
        receipt("DENIAL", 160, reason_code="revoked"),
        receipt("ACTION", 170, scope_class="read", risk_weight=10,
                counterparty_id="cp-a"),
        receipt("BURN", 180, burn_amount=7),
    ]


def fixture_document():
    return {
        "name": "differential_standing_python_rust",
        "kind": "standing",
        "description": "Cross-implementation differential chain for "
                       "Section 16.10 Standing (re-audit N2).",
        "agent_id": "agent-1",
        "eval_time": 200,
        "standing_policy": POLICY,
        "receipts": chain(),
        "expected_standing": EXPECTED,
    }


def run_runner(document):
    """Run the Rust conformance runner over one fixture document
    and return its stdout. Skips (via AssertionError at the call
    site guard) when cargo is unavailable."""
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
    assert run.returncode == 0, run.stdout + run.stderr
    return run.stdout


class TestCrossImplementationDifferential(unittest.TestCase):
    def test_python_matches_hand_computed_vectors(self):
        result = compute_standing(chain(), POLICY, eval_time=200,
                                  agent_id="agent-1")
        for scope_class, fields in EXPECTED.items():
            for field, want in fields.items():
                self.assertEqual(
                    result[scope_class][field], want,
                    "%s.%s" % (scope_class, field))

    def test_rust_conformance_agrees_on_the_same_chain(self):
        cargo = os.path.expanduser("~/.cargo/bin/cargo")
        if not os.path.exists(cargo):
            self.skipTest("cargo not installed; Rust side unverifiable "
                          "in this environment")
        build = subprocess.run(
            [cargo, "build", "--offline", "-p", "acta-verify",
             "--bin", "conformance"],
            cwd=RUST_DIR, capture_output=True, text=True)
        self.assertEqual(build.returncode, 0,
                         build.stdout + build.stderr)
        binary = os.path.join(
            RUST_DIR, "target", "debug", "conformance")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixture_differential.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(fixture_document(), handle)
            run = subprocess.run(
                [binary, tmp, SECRET_FILE],
                capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("PASS fixture_differential.json", run.stdout)
        self.assertIn("spec conformance", run.stdout)


CP_SEED = bytes(range(32))
CP_VK_HEX = ("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1"
             "ddc8664125531b8")
ARGS_HASH = sha256_hex(b"args")
RESULT_HASH = sha256_hex(b"result")
CS_POLICY = {
    "countersign_policy": {"required_for": ["write"]},
    "ceiling_curve": CEILING_CURVE,
    "scope_classes": {"write": {
        "mint_rate": 2, "mint_cap_per_epoch": 1000000,
        "half_life_seconds": 10000000, "hop_attenuation_ppm": 1000000}},
}


def countersigned_receipt(sig_b64):
    return {
        "receipt_type": "ACTION", "timestamp": 100,
        "receipt_id": "diff-cs-1",
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": 3, "delegation_depth": 0,
                   "arguments_hash": ARGS_HASH},
        "result_hash": RESULT_HASH,
        "counterparty_id": "cp-1",
        "counterparty_sig": sig_b64,
    }


class TestS1CountersignedDifferential(unittest.TestCase):
    """Finding S1: one descriptor, byte-identical in both trees,
    proven by a real countersignature crossing between them."""

    def setUp(self):
        self.signer = Ed25519Signer(CP_SEED, key_id="cp-1")
        self.sig_b64 = countersign_outcome(
            self.signer, "agent-1", "tool.call", "write", 100,
            risk_weight=3, receipt_id="diff-cs-1",
            arguments_hash=ARGS_HASH, result_hash=RESULT_HASH)

    def test_python_verifies_own_countersignature(self):
        result = compute_standing(
            [countersigned_receipt(self.sig_b64)], CS_POLICY,
            eval_time=100, agent_id="agent-1",
            counterparty_verifiers={"cp-1": self.signer})
        # mint_rate 2 x risk_weight 3, countersigned at full weight.
        self.assertEqual(result["write"]["standing"], 6)

    def test_rust_verifies_python_countersignature(self):
        fixture_receipt = countersigned_receipt(
            binascii.hexlify(base64.b64decode(self.sig_b64)).decode())
        document = {
            "name": "differential_countersigned_python_to_rust",
            "kind": "standing",
            "description": "A Python-produced countersignature must "
                           "verify in the Rust computation (S1).",
            "agent_id": "agent-1",
            "eval_time": 100,
            "standing_policy": CS_POLICY,
            "counterparty_keys": {"cp-1": CP_VK_HEX},
            "receipts": [fixture_receipt],
            "expected_standing": {"write": {"standing": 6}},
        }
        out = run_runner(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertIn("PASS fixture_differential.json", out)
        self.assertIn("spec conformance", out)

    def test_rust_produced_countersignature_verifies_in_python(self):
        # Fixed vector produced by institutio-core
        # countersign_outcome with seed [9;32] over the descriptor
        # for receipt diff-cs-2 (arguments "aaaa", result "bbbb").
        rust_vk = bytes.fromhex(
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702"
            "eac835e9f618")
        rust_sig = bytes.fromhex(
            "0c31bb6246688a714cc6e5eecab21b9fa1ff2692f5afe200df30"
            "894ece33dc7128d7bec916772b69f7e089409c6eebb0579c16d"
            "0ee04a7c2983b4581c8a8da03")
        verifier = Ed25519Signer(bytes([9] * 32), key_id="cp-1")
        self.assertEqual(verifier.verifying_key_bytes(), rust_vk)
        doc = {
            "receipt_type": "ACTION", "timestamp": 100,
            "receipt_id": "diff-cs-2",
            "agent": {"id": "agent-1"},
            "action": {"name": "tool.call", "scope_class": "write",
                       "risk_weight": 3, "delegation_depth": 0,
                       "arguments_hash": "aaaa"},
            "result_hash": "bbbb",
            "counterparty_id": "cp-1",
            "counterparty_sig": base64.b64encode(rust_sig).decode(),
        }
        result = compute_standing(
            [doc], CS_POLICY, eval_time=100, agent_id="agent-1",
            counterparty_verifiers={"cp-1": verifier})
        self.assertEqual(result["write"]["standing"], 6)


class TestS4SubtreeKillDifferential(unittest.TestCase):
    """Finding S4: killed_agent_ids is the one field name, and a
    named child computes zero in both trees."""

    POLICY = {
        "ceiling_curve": CEILING_CURVE,
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 1000000,
            "half_life_seconds": 10000000,
            "hop_attenuation_ppm": 1000000}},
    }
    RECEIPTS = [
        {"receipt_type": "ACTION", "timestamp": 10,
         "agent": {"id": "agent-child"},
         "action": {"name": "tool.call", "scope_class": "write",
                    "risk_weight": 10, "delegation_depth": 0}},
        {"receipt_type": "KILL-BURN", "timestamp": 20,
         "agent": {"id": "agent-parent"},
         "action": {"name": "standing.kill-burn",
                    "scope_class": "write", "risk_weight": 0},
         "killed_agent_ids": ["agent-child"]},
    ]

    def test_python_child_computes_zero(self):
        result = compute_standing(self.RECEIPTS, self.POLICY,
                                  eval_time=20, agent_id="agent-child")
        self.assertEqual(result["write"]["standing"], 0)
        self.assertTrue(result["write"]["killed"])

    def test_rust_child_computes_zero(self):
        document = {
            "name": "differential_subtree_kill",
            "kind": "standing",
            "description": "A KILL-BURN naming a child in "
                           "killed_agent_ids zeroes the child (S4).",
            "agent_id": "agent-child",
            "eval_time": 20,
            "standing_policy": self.POLICY,
            "receipts": self.RECEIPTS,
            "expected_standing": {"write": {"standing": 0}},
        }
        out = run_runner(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertIn("PASS fixture_differential.json", out)
        self.assertIn("spec conformance", out)


class TestS3IncompletePolicyDifferential(unittest.TestCase):
    """Finding S3: the same incomplete policy (a DENIAL to burn, no
    burn_unit stated) is an error in the Python computation and
    cannot run as spec conformance in the Rust one. The runner's
    prototype-parameter translation can still express the outcome
    with defaults made explicit, which is exactly the label it must
    carry: not spec conformance."""

    POLICY = {
        "ceiling_curve": CEILING_CURVE,
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 100,
            "half_life_seconds": 10000000,
            "hop_attenuation_ppm": 1000000}},
    }
    RECEIPTS = [
        receipt("ACTION", 10, risk_weight=10),
        receipt("DENIAL", 20, reason_code="budget"),
    ]

    def test_python_errors_on_incomplete_policy(self):
        with self.assertRaises(ValueError) as ctx:
            compute_standing(self.RECEIPTS, self.POLICY, eval_time=20)
        self.assertIn("UNSPECIFIED_BY_SPEC", str(ctx.exception))

    def test_rust_cannot_run_it_as_spec_conformance(self):
        document = {
            "name": "differential_incomplete_policy",
            "kind": "standing",
            "description": "Policy omits burn_unit (S3).",
            "agent_id": "agent-1",
            "eval_time": 20,
            "standing_policy": self.POLICY,
            "receipts": self.RECEIPTS,
            "expected_standing": {"write": {"standing": 0}},
        }
        out = run_runner(document)
        if out is None:
            self.skipTest("cargo not installed")
        self.assertIn("prototype-parameter conformance only", out)
        self.assertNotIn("spec conformance:", out)


if __name__ == "__main__":
    unittest.main()

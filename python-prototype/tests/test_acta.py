"""Tests for the Acta receipt core. Author: Gavin Blacklock."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import (  # noqa: E402
    GENESIS_HASH,
    HmacSigner,
    assemble_receipt,
    build_receipt,
    chain_head,
    sha256_hex,
    verify_chain,
)

SIGNER = HmacSigner(b"unit-test-secret", key_id="test-key-1")
AGENT = {"id": "agent-1", "model": "model-x", "model_version": "1.0"}
SCOPE = "tools=[read];resources=[repo];ops=[call]"
T0 = 1763900000


def build_chain(length=3):
    receipts = []
    prior = GENESIS_HASH
    kinds = ["GRANT", "ACTION", "ACTION"]
    for i in range(length):
        receipt = build_receipt(
            SIGNER, "r-%04d" % (i + 1), kinds[i], i, T0 + 60 * i,
            "seat-founder", AGENT, SCOPE, "tool.call",
            sha256_hex(b"args-%d" % i), sha256_hex(b"result-%d" % i), prior,
        )
        receipts.append(receipt)
        prior = receipt["receipt_hash"]
    return receipts


class TestReceiptCore(unittest.TestCase):
    def test_valid_chain_verifies(self):
        result = verify_chain(build_chain(), verifier=SIGNER,
                              expected_key_id="test-key-1")
        self.assertTrue(result.ok, result.message)

    def test_receipt_carries_spec_fields(self):
        receipt = build_chain(1)[0]
        for field in ("delegator", "agent", "scope_granted", "action",
                      "result_hash", "effects", "timestamp",
                      "prior_receipt_hash"):
            self.assertIn(field, receipt)
        self.assertEqual(receipt["agent"]["model"], "model-x")
        self.assertEqual(receipt["agent"]["model_version"], "1.0")
        self.assertIn("arguments_hash", receipt["action"])
        self.assertIn("sub_delegations", receipt["effects"])

    def test_tampered_receipt_detected(self):
        chain = build_chain()
        chain[1]["result_hash"] = sha256_hex(b"forged")
        result = verify_chain(chain, verifier=SIGNER)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "TAMPERED")
        self.assertEqual(result.failure_index, 1)

    def test_tampered_envelope_signature_detected(self):
        chain = build_chain()
        chain[0]["envelope"]["signatures"][0]["signature"] = "AAAA"
        result = verify_chain(chain, verifier=SIGNER)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "SIGNATURE_INVALID")

    def test_reordered_chain_detected(self):
        chain = build_chain()
        chain[1], chain[2] = chain[2], chain[1]
        result = verify_chain(chain, verifier=SIGNER)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "REORDERED")

    def test_truncation_detected_against_expected_head(self):
        chain = build_chain()
        head = chain_head(chain)
        result = verify_chain(chain[:2], verifier=SIGNER, expected_head=head)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "TRUNCATED")

    def test_truncation_detected_against_expected_length(self):
        chain = build_chain()
        result = verify_chain(chain[:2], verifier=SIGNER, expected_length=3)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "TRUNCATED")

    def test_wrong_key_id_detected(self):
        result = verify_chain(build_chain(), verifier=SIGNER,
                              expected_key_id="other-key")
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "KEY_ID_MISMATCH")

    def test_denial_requires_reason_code_on_build(self):
        with self.assertRaises(ValueError):
            build_receipt(
                SIGNER, "r-deny", "DENIAL", 0, T0, "seat-founder", AGENT,
                SCOPE, "tool.call", sha256_hex(b"a"), sha256_hex(b""),
                GENESIS_HASH,
            )

    def test_denial_with_each_reason_code_builds_and_verifies(self):
        for code in ("revoked", "scope", "manifest-mismatch", "budget",
                     "standing-ceiling"):
            denial = build_receipt(
                SIGNER, "r-deny-" + code, "DENIAL", 0, T0, "seat-founder",
                AGENT, SCOPE, "tool.call", sha256_hex(b"a"),
                sha256_hex(b""), GENESIS_HASH, reason_code=code,
            )
            result = verify_chain([denial], verifier=SIGNER)
            self.assertTrue(result.ok, code)

    def test_denial_without_reason_code_fails_verification(self):
        payload = {
            "receipt_version": "0.1",
            "receipt_id": "r-bad",
            "receipt_type": "DENIAL",
            "sequence": 0,
            "timestamp": T0,
            "delegator": "seat-founder",
            "agent": AGENT,
            "scope_granted": SCOPE,
            "action": {"name": "tool.call",
                       "arguments_hash": sha256_hex(b"a")},
            "result_hash": sha256_hex(b""),
            "effects": {"artifacts_changed": [], "external_calls": [],
                        "sub_delegations": []},
            "prior_receipt_hash": GENESIS_HASH,
        }
        receipt = assemble_receipt(payload, SIGNER)
        result = verify_chain([receipt], verifier=SIGNER)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_code, "DENIAL_REASON_MISSING")

    def test_deterministic_rebuild(self):
        self.assertEqual(build_chain(), build_chain())

    def test_deepcopy_tamper_of_effects_detected(self):
        chain = build_chain()
        forged = copy.deepcopy(chain)
        forged[2]["effects"]["artifacts_changed"] = ["repo/evil.txt"]
        result = verify_chain(forged, verifier=SIGNER)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()

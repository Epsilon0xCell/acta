"""Tests for Institutio charter validation. Author: Gavin Blacklock."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import HmacSigner  # noqa: E402
from institutio import (  # noqa: E402
    compute_charter_hash,
    example_charter,
    sign_charter,
    validate_charter,
    validate_charter_chain,
)

SIGNER = HmacSigner(b"unit-test-secret", key_id="founder-root-key-1")
VERIFIERS = {"founder-root-key-1": SIGNER}


class TestCharter(unittest.TestCase):
    def test_example_charter_is_valid(self):
        signed = sign_charter(example_charter(), SIGNER)
        self.assertEqual(
            validate_charter(signed, verifiers=VERIFIERS,
                             pinned_founder_key_ids={"founder-root-key-1"}),
            [])

    def test_child_delegation_exceeding_parent_fails(self):
        charter = example_charter()
        charter["authority_manifests"][1]["scope"]["tools"] = ["read", "write"]
        errors = validate_charter(charter)
        self.assertTrue(any("exceeds parent" in e for e in errors), errors)

    def test_child_limit_above_parent_fails(self):
        charter = example_charter()
        charter["authority_manifests"][1]["scope"]["limits"]["external_calls"] = 50
        errors = validate_charter(charter)
        self.assertTrue(any("exceeds parent" in e for e in errors), errors)

    def test_child_dropping_parent_limit_fails(self):
        charter = example_charter()
        del charter["authority_manifests"][1]["scope"]["limits"]["spend_units"]
        errors = validate_charter(charter)
        self.assertTrue(any("exceeds parent" in e for e in errors), errors)

    def test_manifest_wider_than_grantor_seat_fails(self):
        charter = example_charter()
        charter["authority_manifests"][0]["scope"]["tools"] = [
            "read", "write", "exec", "admin"]
        errors = validate_charter(charter)
        self.assertTrue(any("exceeds parent" in e for e in errors), errors)

    def test_sub_delegation_without_permission_fails(self):
        charter = example_charter()
        charter["authority_manifests"][0]["sub_delegation_allowed"] = False
        errors = validate_charter(charter)
        self.assertTrue(any("does not permit sub-delegation" in e
                            for e in errors), errors)

    def test_delegation_loop_fails(self):
        charter = example_charter()
        charter["authority_manifests"].append({
            "manifest_id": "m-loop",
            "grantor_seat": "helper",
            "grantee_seat": "operator",
            "scope": {"tools": ["read"], "resources": ["repo"],
                      "operations": ["call"],
                      "limits": {"external_calls": 1, "spend_units": 1}},
            "issued_at": 1763900200,
            "expires_at": 1766500000,
            "sub_delegation_allowed": False,
        })
        errors = validate_charter(charter)
        self.assertTrue(any("loop" in e for e in errors), errors)

    def test_unknown_budget_ref_fails(self):
        charter = example_charter()
        charter["authority_manifests"][0]["budget_ref"] = "b-missing"
        errors = validate_charter(charter)
        self.assertTrue(any("unknown budget" in e for e in errors), errors)

    def test_signed_charter_hash_verifies(self):
        signed = sign_charter(example_charter(), SIGNER)
        self.assertEqual(
            validate_charter(signed, verifiers=VERIFIERS,
                             pinned_founder_key_ids={"founder-root-key-1"}),
            [])
        forged = copy.deepcopy(signed)
        forged["org"]["name"] = "Forged Firm"
        self.assertTrue(any("charter_hash" in e
                            for e in validate_charter(
                                forged, verifiers=VERIFIERS,
                                pinned_founder_key_ids={
                                    "founder-root-key-1"})))

    def test_charter_chain_links_amendments(self):
        founding = sign_charter(example_charter(), SIGNER)
        amendment_doc = example_charter()
        amendment_doc["predecessor_charter_hash"] = compute_charter_hash(founding)
        amendment_doc["org"]["name"] = "Example Firm Amended"
        amendment = sign_charter(amendment_doc, SIGNER)
        self.assertEqual(validate_charter_chain(
            [founding, amendment], verifiers=VERIFIERS,
            founder_key_ids={"founder-root-key-1"}), [])

    def test_charter_chain_broken_link_fails(self):
        founding = sign_charter(example_charter(), SIGNER)
        amendment_doc = example_charter()
        amendment_doc["predecessor_charter_hash"] = "f" * 64
        amendment = sign_charter(amendment_doc, SIGNER)
        errors = validate_charter_chain([founding, amendment],
                                        verifiers=VERIFIERS)
        self.assertTrue(any("amendment chain is broken" in e
                            for e in errors), errors)


if __name__ == "__main__":
    unittest.main()

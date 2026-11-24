#!/usr/bin/env python3
"""Fixture runner: check every fixture against its expected verdict.

Author: Gavin Blacklock

Run from the code directory: python3 fixtures/run_fixtures.py
Exit code 0 means every fixture behaved as expected.
"""

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.dirname(HERE)
sys.path.insert(0, CODE_DIR)

from acta import HmacSigner, verify_chain  # noqa: E402
from institutio import (  # noqa: E402
    compute_standing, validate_charter, validate_charter_chain,
    verify_checkpoint,
)

SECRET = open(os.path.join(HERE, "test_secret.txt"), "rb").read().strip()
VERIFIER = HmacSigner(SECRET, key_id="acta-test-key-1")
CHARTER_VERIFIERS = {
    "founder-root-key-1": HmacSigner(SECRET, key_id="founder-root-key-1"),
}
WITNESS_VERIFIERS = {
    key_id: HmacSigner(SECRET, key_id=key_id)
    for key_id in ("w-1", "w-2", "w-3", "w-4", "w-5",
                   "checkpoint-issuer-1")
}


def check_fixture(path):
    with open(path, "r", encoding="utf-8") as handle:
        fixture = json.load(handle)
    if fixture["kind"] == "standing":
        result = compute_standing(
            fixture["receipts"], fixture.get("standing_policy"),
            eval_time=fixture.get("eval_time"),
            agent_id=fixture.get("agent_id"),
        )
        for scope_class, expected in fixture["expected_standing"].items():
            entry = result.get(scope_class)
            if entry is None:
                return False, "no Standing entry for class %r" % scope_class
            for key, value in expected.items():
                if entry.get(key) != value:
                    return False, (
                        "class %s: %s is %r, expected %r"
                        % (scope_class, key, entry.get(key), value)
                    )
        return True, "Standing recomputed as expected: %s" % (
            {cls: e["standing"] for cls, e in result.items()},)
    expected = fixture["expected_verdict"]
    if fixture["kind"] == "receipt_bundle":
        receipts = fixture["bundle"]["receipts"]
        result = verify_chain(
            receipts, verifier=VERIFIER,
            expected_key_id="acta-test-key-1",
            expected_head=fixture.get("verify_expected_head"),
            expected_length=fixture.get("verify_expected_length"),
        )
        if expected == "valid":
            if not result.ok:
                return False, "expected valid, got %s" % result.message
            last = fixture.get("expected_last_receipt")
            if last:
                tail = receipts[-1]
                for key, value in last.items():
                    if tail.get(key) != value:
                        return False, (
                            "last receipt %s is %r, expected %r"
                            % (key, tail.get(key), value)
                        )
            return True, "chain verified as expected"
        if result.ok:
            return False, "expected invalid, chain verified"
        code = fixture.get("expected_code")
        if code and result.failure_code != code:
            return False, "expected failure code %s, got %s (%s)" % (
                code, result.failure_code, result.message)
        return True, "rejected as expected: %s" % result.failure_code
    if fixture["kind"] == "charter":
        errors = validate_charter(
            fixture["charter"], verifiers=CHARTER_VERIFIERS,
            pinned_founder_key_ids={"founder-root-key-1"})
        if expected == "valid":
            return (not errors), "charter errors: %s" % errors
        if not errors:
            return False, "expected invalid charter, validation passed"
        needle = fixture.get("expected_error_contains")
        if needle and not any(needle in error for error in errors):
            return False, "no error containing %r in %s" % (needle, errors)
        return True, "rejected as expected: %d errors" % len(errors)
    if fixture["kind"] == "charter_chain":
        errors = validate_charter_chain(
            fixture["charters"], verifiers=CHARTER_VERIFIERS,
            founder_key_ids={"founder-root-key-1"})
        if expected == "valid":
            return (not errors), "charter chain errors: %s" % errors
        if not errors:
            return False, "expected invalid charter chain, validation passed"
        needle = fixture.get("expected_error_contains")
        if needle and not any(needle in error for error in errors):
            return False, "no error containing %r in %s" % (needle, errors)
        return True, "rejected as expected: %d errors" % len(errors)
    if fixture["kind"] == "checkpoint":
        errors = verify_checkpoint(
            fixture["checkpoint"], fixture["receipts"],
            fixture.get("standing_policy"),
            witness_verifiers=WITNESS_VERIFIERS)
        if expected == "valid":
            return (not errors), "checkpoint errors: %s" % errors
        if not errors:
            return False, "expected invalid checkpoint, verification passed"
        needle = fixture.get("expected_error_contains")
        if needle and not any(needle in error for error in errors):
            return False, "no error containing %r in %s" % (needle, errors)
        return True, "rejected as expected: %d errors" % len(errors)
    return False, "unknown fixture kind %r" % fixture.get("kind")


def main():
    paths = sorted(glob.glob(os.path.join(HERE, "fixture_*.json")))
    failures = 0
    for path in paths:
        ok, detail = check_fixture(path)
        print("%s %s: %s" % ("PASS" if ok else "FAIL",
                             os.path.basename(path), detail))
        if not ok:
            failures += 1
    print("fixtures: %d run, %d passed, %d failed"
          % (len(paths), len(paths) - failures, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

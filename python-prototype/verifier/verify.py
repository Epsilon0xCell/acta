#!/usr/bin/env python3
"""Acta one-file offline verifier.

Author: Gavin Blacklock

Self-contained: Python 3 standard library only, no imports from the
acta package, no network access. A stranger can run this file against
a receipt bundle and reach the same verdict as the reference code.

Usage:
    python3 verify.py BUNDLE.json --secret-file SECRET.txt
    python3 verify.py BUNDLE.json --secret-file SECRET.txt --key-id KEY
    python3 verify.py BUNDLE.json --secret-file SECRET.txt \
        --expected-head HEX --expected-length N

The bundle is a JSON object {"bundle_version": "0.1", "receipts": [...]}
or a bare list of receipts. The secret file holds the shared secret for
the v0.1 placeholder HMAC-SHA256 signature scheme (see the README in
the code directory: real asymmetric signing replaces this behind the
signer interface). --key-id checks that every receipt carries a
signature from that key identifier.

Prints one plain verdict. On failure it names the first failure
precisely: receipt index, receipt id, failure code, and reason.
Exit code 0 means the bundle verified; 1 means it did not.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys

PAYLOAD_TYPE = "application/vnd.acta.receipt.v0.1+json"
GENESIS_HASH = "0" * 64
DENIAL_REASON_CODES = (
    "revoked",
    "scope",
    "manifest-mismatch",
    "budget",
    "standing-ceiling",
)
RECEIPT_TYPES = (
    "GRANT", "ACTION", "DENIAL", "BURN", "PROMOTION", "DEMOTION",
    "REVOCATION", "KILL-BURN",
)


def canonical_bytes(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def is_hash_hex(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def pae(payload_type, payload):
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def sign(secret, payload_type, payload):
    mac = hmac.new(secret, pae(payload_type, payload), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def payload_dict(receipt):
    return {
        key: value
        for key, value in receipt.items()
        if key not in ("receipt_hash", "envelope")
    }


def fail(index, receipt, code, message):
    receipt_id = receipt.get("receipt_id", "?") if isinstance(receipt, dict) else "?"
    return "FAIL receipt %s (%s): %s: %s" % (index, receipt_id, code, message)


def verify(receipts, secret, key_id=None, expected_head=None, expected_length=None):
    """Return (ok, verdict_line). Mirrors acta.receipts.verify_chain."""
    if not isinstance(receipts, list):
        return False, "FAIL: bundle receipts must be a list"
    if len(receipts) == 0:
        return False, (
            "FAIL: EMPTY_CHAIN: the bundle carries no receipts; "
            "an empty chain verifies nothing")
    previous_hash = GENESIS_HASH
    seen_receipt_ids = set()
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            return False, fail(index, {}, "INVALID_RECEIPT", "receipt is not an object")
        # Duplicate receipt identities are invalid (minor s6),
        # mirroring acta.receipts.verify_chain.
        if receipt.get("receipt_id") is not None:
            if receipt["receipt_id"] in seen_receipt_ids:
                return False, fail(
                    index, receipt, "DUPLICATE_RECEIPT_ID",
                    "receipt_id duplicates an earlier receipt in "
                    "this chain; receipt identities are unique")
            seen_receipt_ids.add(receipt["receipt_id"])
        for field in (
            "receipt_version", "receipt_id", "receipt_type",
            "sequence", "timestamp",
            "delegator", "agent", "scope_granted", "action",
            "result_hash", "effects", "prior_receipt_hash",
        ):
            if field not in receipt:
                return False, fail(index, receipt, "INVALID_RECEIPT",
                                   "missing required field: %s" % field)
        if receipt["receipt_type"] not in RECEIPT_TYPES:
            return False, fail(index, receipt, "INVALID_RECEIPT",
                               "unknown receipt_type: %r" % receipt["receipt_type"])
        if receipt["receipt_type"] == "DENIAL" and (
            receipt.get("reason_code") not in DENIAL_REASON_CODES
        ):
            return False, fail(
                index, receipt, "DENIAL_REASON_MISSING",
                "DENIAL receipt has no valid reason_code (got %r); a "
                "denial without a reason code is non-conforming"
                % (receipt.get("reason_code"),),
            )
        if receipt["sequence"] != index:
            return False, fail(
                index, receipt, "REORDERED",
                "sequence is %r, expected %d; the chain is reordered "
                "or has a gap" % (receipt["sequence"], index),
            )
        if receipt["prior_receipt_hash"] != previous_hash:
            return False, fail(
                index, receipt, "CHAIN_BREAK",
                "prior_receipt_hash does not match the hash of the "
                "previous receipt",
            )
        recomputed = sha256_hex(canonical_bytes(payload_dict(receipt)))
        if recomputed != receipt.get("receipt_hash"):
            return False, fail(
                index, receipt, "TAMPERED",
                "recomputed hash does not match the recorded "
                "receipt_hash; a signed field was altered",
            )
        envelope = receipt.get("envelope")
        if not isinstance(envelope, dict) or envelope.get("payload_type") != PAYLOAD_TYPE:
            return False, fail(index, receipt, "INVALID_ENVELOPE",
                               "missing or mistyped DSSE envelope")
        try:
            envelope_payload = base64.b64decode(envelope["payload"].encode("ascii"))
        except Exception:
            return False, fail(index, receipt, "INVALID_ENVELOPE",
                               "envelope payload is not valid base64")
        if envelope_payload != canonical_bytes(payload_dict(receipt)):
            return False, fail(
                index, receipt, "TAMPERED",
                "envelope payload bytes do not match the receipt fields",
            )
        signatures = envelope.get("signatures") or []
        if not signatures:
            return False, fail(index, receipt, "UNSIGNED",
                               "envelope carries no signatures")
        if key_id is not None and not any(
            sig.get("key_id") == key_id for sig in signatures
        ):
            return False, fail(
                index, receipt, "KEY_ID_MISMATCH",
                "no signature from expected key id %r" % key_id,
            )
        matched = [
            sig for sig in signatures
            if key_id is None or sig.get("key_id") == key_id
        ]
        if secret is not None and not any(
            hmac.compare_digest(sign(secret, PAYLOAD_TYPE, envelope_payload),
                                sig.get("signature", ""))
            for sig in matched
        ):
            return False, fail(index, receipt, "SIGNATURE_INVALID",
                               "envelope signature does not verify")
        previous_hash = receipt["receipt_hash"]
    if expected_length is not None and len(receipts) != expected_length:
        code = "TRUNCATED" if len(receipts) < expected_length else "LENGTH_MISMATCH"
        return False, "FAIL: %s: chain has %d receipts, expected %d" % (
            code, len(receipts), expected_length)
    if expected_head is not None and previous_hash != expected_head:
        return False, (
            "FAIL: TRUNCATED: chain head %s does not match the expected "
            "head %s; the chain is truncated or substituted"
            % (previous_hash, expected_head)
        )
    return True, "PASS: chain verified: %d receipts, head %s" % (
        len(receipts), previous_hash)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify an Acta receipt bundle offline."
    )
    parser.add_argument("bundle", help="path to the receipt bundle JSON file")
    parser.add_argument("--secret-file", required=True,
                        help="file holding the shared secret for the "
                             "placeholder HMAC signature scheme")
    parser.add_argument("--key-id", default=None,
                        help="expected signer key identifier")
    parser.add_argument("--expected-head", default=None,
                        help="expected chain head hash (detects truncation)")
    parser.add_argument("--expected-length", type=int, default=None,
                        help="expected number of receipts (detects truncation)")
    args = parser.parse_args(argv)

    with open(args.secret_file, "rb") as handle:
        secret = handle.read().strip()
    if not secret:
        print("FAIL: secret file is empty")
        return 1
    with open(args.bundle, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    receipts = bundle.get("receipts") if isinstance(bundle, dict) else bundle
    ok, verdict = verify(
        receipts, secret, key_id=args.key_id,
        expected_head=args.expected_head, expected_length=args.expected_length,
    )
    print(verdict)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

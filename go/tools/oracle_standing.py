#!/usr/bin/env python3
"""Differential harness oracle: run the Python prototype's
ComputeStanding as a black-box oracle over a case file and print
the result as JSON. This file is test harness, not part of the Go
implementation; the Go implementation was written from the
specification and never imports or copies the prototype.

Case file: {receipts, standing_policy, eval_time, agent_id,
counterparty_seeds: {counterparty_id: seed_hex},
validate_only: bool}

Output: {"ok": true, "result": {...}} or {"ok": false, "error": "..."}
or, with the single argument "pubkey SEED_HEX", the Ed25519 public
key hex for that seed.

Author: Gavin Blacklock
"""
import json
import sys

sys.path.insert(0, __file__.rsplit("/tools/", 1)[0] + "/../code")

from acta.signing import Ed25519Signer, ed25519_public_key  # noqa: E402
from institutio import standing as S  # noqa: E402


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "pubkey":
        print(ed25519_public_key(bytes.fromhex(sys.argv[2])).hex())
        return
    with open(sys.argv[1]) as fh:
        case = json.load(fh)
    verifiers = {}
    for cp_id, seed_hex in (case.get("counterparty_seeds") or {}).items():
        verifiers[cp_id] = Ed25519Signer(seed=bytes.fromhex(seed_hex), key_id=cp_id + "-key")
    try:
        if case.get("validate_only"):
            errors = S.validate_standing_policy(case["standing_policy"])
            if isinstance(errors, (list, tuple)) and errors:
                print(json.dumps({"ok": False, "error": "; ".join(str(e) for e in errors)}))
                return
            print(json.dumps({"ok": True, "result": {}}))
            return
        result = S.compute_standing(
            case["receipts"],
            case["standing_policy"],
            eval_time=case.get("eval_time"),
            agent_id=case.get("agent_id"),
            counterparty_verifiers=verifiers or None,
        )
        print(json.dumps({"ok": True, "result": result}))
    except Exception as exc:  # oracle error surface: any exception is a rejection
        print(json.dumps({"ok": False, "error": str(exc)}))


if __name__ == "__main__":
    main()

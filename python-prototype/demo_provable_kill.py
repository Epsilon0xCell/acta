#!/usr/bin/env python3
"""The Provable Kill, wired end to end (specification Section 7).

Author: Gavin Blacklock

An executable narrative, run from the code directory:

    python3 demo_provable_kill.py

A rogue seat holds a genuine delegation and works under it for a
simulated 7 days of receipt history (timestamps are data, generated
deterministically; no wall clock is read). The founder then revokes
the delegation and burns the rogue's Standing to zero (the KILL-BURN
checkpoint, Section 16.6). The rogue attempts three post-revocation
actions: a direct action, an action through a child sub-delegation
minted before the revocation, and a replay of a previously valid
authorisation. All three are denied by ToolGate and receipted. A
sibling seat's Standing checkpoint recomputes unchanged across the
kill, and the sibling completes an action in the same window:
the kill is surgical, not a shutdown.

The resulting bundle is written to provable_kill_bundle.json and
checked with the standalone one-file verifier (verifier/verify.py)
in a subprocess. The signing secret is the published fixture test
secret (fixtures/test_secret.txt), so anyone can reproduce the run
and the verification. Exit code 0 means every expectation held.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from acta import HmacSigner, sha256_hex, verify_chain  # noqa: E402
from institutio import build_checkpoint, countersign_outcome  # noqa: E402
from toolgate import ToolGate  # noqa: E402

SECRET = open(os.path.join(HERE, "fixtures", "test_secret.txt"),
              "rb").read().strip()
KEY_ID = "acta-test-key-1"
FOUNDER_KEY = "founder-root-key-1"
SIGNER = HmacSigner(SECRET, key_id=KEY_ID)

# Counterparties hold their own keys and countersign outcomes with
# real signatures over the outcome descriptor (audit finding M2).
# The gate and the Standing computation verify these signatures;
# a string that merely looks like a signature mints nothing.
CP_ALPHA = HmacSigner(b"counterparty-alpha-secret",
                      key_id="counterparty-alpha")
CP_BETA = HmacSigner(b"counterparty-beta-secret",
                     key_id="counterparty-beta")
COUNTERPARTY_VERIFIERS = {
    "counterparty-alpha": CP_ALPHA,
    "counterparty-beta": CP_BETA,
}


def countersig(gate, signer, agent, action_name, arguments, when,
               scope_class="write", risk_weight=3):
    """A countersignature over the bound outcome descriptor.

    The descriptor names the receipt the gate is about to issue
    (its id is a deterministic function of chain length), the
    arguments and result hashes, and the risk weight, so the
    signature cannot be replayed onto another receipt or
    re-weighted (re-audit finding M2).
    """
    arguments_hash = sha256_hex(arguments.encode("utf-8"))
    result_hash = sha256_hex(("result:" + arguments_hash).encode("utf-8"))
    return countersign_outcome(
        signer, agent["id"], action_name, scope_class, when,
        risk_weight=risk_weight, receipt_id=gate.next_receipt_id(),
        arguments_hash=arguments_hash, result_hash=result_hash)

DAY = 86400
T0 = 1763900000  # deterministic base time; timestamps are data

WRITE_HASH = sha256_hex(b"tool-definition:repo.write:v1")
READ_HASH = sha256_hex(b"tool-definition:repo.read:v1")

# The policy is stated completely (second re-audit finding S3):
# every field Section 16.10 assigns to the policy is present, with
# no computation default behind it. The ceiling curve is the tier
# set the prototype once defaulted to, now the charter's own
# stated curve. The half-life is thirty days, so the demo's
# seven-day history decays by zero whole half-lives.
_ALL_MULTIPLIERS = {"revoked": 2, "scope": 2, "manifest-mismatch": 1,
                    "budget": 1, "standing-ceiling": 1}
_DEMO_CURVE = [
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
POLICY = {
    "countersign_policy": {"required_for": ["write", "read"]},
    "epoch_seconds": DAY,
    "ceiling_curve": _DEMO_CURVE,
    "scope_classes": {
        # correlated_burn_fraction_ppm is a per-class field
        # (Section 16.10 decision 7); it was stated at policy
        # level here under the retired top-level merge, and
        # decision 24 row (e) reads class fields class-locally.
        "write": {"mint_rate": 2, "mint_cap_per_epoch": 100,
                  "half_life_seconds": 30 * DAY,
                  "hop_attenuation_ppm": 1000000,
                  "correlated_burn_fraction_ppm": 250000,
                  "burn_unit": 5, "burn_multipliers": _ALL_MULTIPLIERS},
        "read": {"mint_rate": 1, "mint_cap_per_epoch": 100,
                 "half_life_seconds": 30 * DAY,
                 "hop_attenuation_ppm": 1000000,
                 "correlated_burn_fraction_ppm": 250000,
                 "burn_unit": 5, "burn_multipliers": _ALL_MULTIPLIERS},
    },
}

ROGUE = {"id": "agent-rogue-1", "model": "model-x", "model_version": "1.0"}
SIBLING = {"id": "agent-sibling-1", "model": "model-x", "model_version": "1.0"}
CHILD = {"id": "agent-rogue-child-1", "model": "model-x",
         "model_version": "1.0"}

FAILURES = []


def check(label, condition, detail=""):
    print("  [%s] %s%s" % ("ok" if condition else "FAIL", label,
                           (" :: " + detail) if detail else ""))
    if not condition:
        FAILURES.append(label)


def scope(tools, spend):
    return {"tools": tools, "resources": ["repo"], "operations": ["call"],
            "limits": {"spend_units": spend, "external_calls": 100}}


def build_gate():
    gate = ToolGate(SIGNER, standing_policy=POLICY,
                    authorized_key_ids=(FOUNDER_KEY,),
                    counterparty_verifiers=COUNTERPARTY_VERIFIERS)
    gate.register_tool("repo.write", WRITE_HASH, scope_class="write",
                       risk_weight=3)
    gate.register_tool("repo.read", READ_HASH, scope_class="read",
                       risk_weight=1)
    gate.add_delegation({
        "manifest_id": "m-rogue", "grantor_seat": "founder",
        "grantee_seat": "rogue", "agent": ROGUE,
        "scope": scope(["repo.write", "repo.read"], 10000),
    })
    gate.add_delegation({
        "manifest_id": "m-rogue-child", "grantor_seat": "rogue",
        "grantee_seat": "rogue-child", "agent": CHILD,
        "parent_manifest_id": "m-rogue",
        "scope": scope(["repo.write"], 1000),
    })
    gate.add_delegation({
        "manifest_id": "m-sibling", "grantor_seat": "founder",
        "grantee_seat": "sibling", "agent": SIBLING,
        "scope": scope(["repo.write", "repo.read"], 10000),
    })
    return gate


def main():
    gate = build_gate()
    print("== The Provable Kill (specification Section 7) ==")

    print("Step 1: grants issued for the rogue, its child, and a sibling")
    gate.issue_grant("m-rogue", T0)
    gate.issue_grant("m-rogue-child", T0 + 10)
    gate.issue_grant("m-sibling", T0 + 20)

    print("Step 2: the rogue works for a simulated 7 days, receipted")
    first_auth = None
    first_receipt_id = None
    for day in range(7):
        for slot in range(2):
            when = T0 + day * DAY + 3600 + slot * 600
            decision = gate.propose(
                "m-rogue", "repo.write", WRITE_HASH,
                "rogue-work-day-%d-%d" % (day, slot), when,
                budget_cost=3,
                counterparty_id="counterparty-alpha",
                counterparty_sig=countersig(
                    gate, CP_ALPHA, ROGUE, "repo.write",
                    "rogue-work-day-%d-%d" % (day, slot), when),
                authorisation_id="auth-rogue-%d-%d" % (day, slot),
            )
            if first_auth is None:
                first_auth = "auth-rogue-0-0"
                first_receipt_id = decision.receipt["receipt_id"]
            check("rogue day %d action %d allowed" % (day, slot),
                  decision.allowed)
    child_decision = gate.propose(
        "m-rogue-child", "repo.write", WRITE_HASH, "child-work-0",
        T0 + 6 * DAY + 7200, budget_cost=3,
        counterparty_id="counterparty-alpha",
        counterparty_sig=countersig(
            gate, CP_ALPHA, CHILD, "repo.write", "child-work-0",
            T0 + 6 * DAY + 7200),
    )
    check("rogue child action allowed before the kill",
          child_decision.allowed)
    for slot in range(3):
        decision = gate.propose(
            "m-sibling", "repo.write", WRITE_HASH,
            "sibling-work-%d" % slot, T0 + slot * DAY + 1800,
            budget_cost=3, counterparty_id="counterparty-beta",
            counterparty_sig=countersig(
                gate, CP_BETA, SIBLING, "repo.write",
                "sibling-work-%d" % slot, T0 + slot * DAY + 1800),
        )
        check("sibling action %d allowed" % slot, decision.allowed)

    kill_time = T0 + 7 * DAY
    rogue_before = build_checkpoint(
        gate.chain, POLICY, eval_time=kill_time, agent_id=ROGUE["id"],
        org_id="org-example-0001",
        counterparty_verifiers=COUNTERPARTY_VERIFIERS)
    sibling_before = build_checkpoint(
        gate.chain, POLICY, eval_time=kill_time, agent_id=SIBLING["id"],
        org_id="org-example-0001",
        counterparty_verifiers=COUNTERPARTY_VERIFIERS)
    print("  rogue Standing before the kill: %s"
          % rogue_before["standing_vector"])
    print("  sibling Standing before the kill: %s"
          % sibling_before["standing_vector"])
    check("rogue earned Standing over 7 days",
          rogue_before["standing_vector"].get("write", 0) > 0)

    print("Step 3: the founder revokes the rogue delegation (ticket T1)")
    revocation = gate.revoke("m-rogue", kill_time + 60, FOUNDER_KEY)
    print("  revocation receipt %s at sequence %d"
          % (revocation["receipt_id"], revocation["sequence"]))

    print("Step 4: the KILL-BURN checkpoint (ticket T11, Section 16.6)")
    kill_burn = gate.kill_burn("m-rogue", kill_time + 120, FOUNDER_KEY)
    rogue_after = build_checkpoint(
        gate.chain, POLICY, eval_time=kill_time + 120,
        agent_id=ROGUE["id"], org_id="org-example-0001",
        counterparty_verifiers=COUNTERPARTY_VERIFIERS)
    sibling_after_kill = build_checkpoint(
        gate.chain, POLICY, eval_time=kill_time + 120,
        agent_id=SIBLING["id"], org_id="org-example-0001",
        counterparty_verifiers=COUNTERPARTY_VERIFIERS)
    print("  KILL-BURN receipt %s: pre-kill Standing %s, post-kill %s"
          % (kill_burn["receipt_id"],
             kill_burn["verdict"]["pre_kill_standing"],
             rogue_after["standing_vector"]))
    check("rogue Standing is zero in every class after the kill",
          all(value == 0 for value in rogue_after["standing_vector"].values()),
          str(rogue_after["standing_vector"]))
    check("sibling Standing checkpoint recomputes unchanged",
          sibling_after_kill["standing_vector"]
          == sibling_before["standing_vector"],
          "%s vs %s" % (sibling_after_kill["standing_vector"],
                        sibling_before["standing_vector"]))

    print("Step 5: three post-revocation attempts, all denied (Section 7.1)")
    attempts = []
    attempts.append(("a", "direct action under the revoked delegation",
                     gate.propose(
                         "m-rogue", "repo.write", WRITE_HASH,
                         "rogue-attack-direct", kill_time + 600,
                         budget_cost=3,
                         authorisation_id="auth-rogue-attack-a")))
    attempts.append(("b", "action through the pre-revocation child "
                          "sub-delegation",
                     gate.propose(
                         "m-rogue-child", "repo.write", WRITE_HASH,
                         "rogue-attack-child", kill_time + 660,
                         budget_cost=3,
                         authorisation_id="auth-child-attack")))
    attempts.append(("c", "replay of a previously valid authorisation",
                     gate.propose(
                         "m-rogue", "repo.write", WRITE_HASH,
                         "rogue-work-day-0-0", kill_time + 720,
                         budget_cost=3, replay_of=first_auth,
                         authorisation_id=first_auth)))
    for label, description, decision in attempts:
        receipt = decision.receipt
        grounds = receipt["verdict"].get("independent_grounds", [])
        print("  attempt (%s) %s: DENIED, reason %s, receipt %s"
              % (label, description, decision.reason_code,
                 receipt["receipt_id"]))
        check("attempt (%s) denied" % label, not decision.allowed)
        check("attempt (%s) reason code is revoked" % label,
              decision.reason_code == "revoked")
        check("attempt (%s) carries the Standing second ground" % label,
              "standing-ceiling" in grounds, str(grounds))
        check("attempt (%s) emitted a BURN receipt" % label,
              decision.burn_receipt is not None
              and decision.burn_receipt["receipt_type"] == "BURN")
    check("the replay names the consumed authorisation",
          attempts[2][2].receipt["verdict"]["detail"].find(first_auth) >= 0
          or attempts[2][2].receipt["verdict"]["detail"].find(
              first_receipt_id) >= 0)

    print("Step 6: continuity, the sibling acts in the same window (T7)")
    decision = gate.propose(
        "m-sibling", "repo.write", WRITE_HASH, "sibling-work-after-kill",
        kill_time + 900, budget_cost=3,
        counterparty_id="counterparty-beta",
        counterparty_sig=countersig(
            gate, CP_BETA, SIBLING, "repo.write",
            "sibling-work-after-kill", kill_time + 900),
    )
    print("  sibling post-kill action: %s, receipt %s"
          % ("ALLOW" if decision.allowed else "DENY",
             decision.receipt["receipt_id"]))
    check("sibling action allowed after the kill", decision.allowed)

    print("Step 7: the bundle verifies, in-process and standalone")
    result = verify_chain(gate.chain, verifier=SIGNER, expected_key_id=KEY_ID)
    check("in-process chain verification", result.ok, result.message)
    bundle = {"bundle_version": "0.1", "receipts": gate.chain}
    bundle_path = os.path.join(HERE, "provable_kill_bundle.json")
    with open(bundle_path, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2, sort_keys=True)
        handle.write("\n")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "verifier", "verify.py"),
         bundle_path, "--secret-file",
         os.path.join(HERE, "fixtures", "test_secret.txt"),
         "--key-id", KEY_ID],
        capture_output=True, text=True,
    )
    print("  standalone verifier: %s" % proc.stdout.strip())
    check("standalone verifier PASS", proc.returncode == 0
          and proc.stdout.startswith("PASS"), proc.stdout + proc.stderr)

    denials = [r for r in gate.chain if r["receipt_type"] == "DENIAL"]
    actions_after = [r for r in gate.chain
                     if r["receipt_type"] == "ACTION"
                     and r["timestamp"] >= kill_time]
    print("Summary: %d receipts, %d post-kill denials (all reason "
          "revoked), %d sibling actions at or after the kill time"
          % (len(gate.chain), len(denials), len(actions_after)))
    if FAILURES:
        print("DEMO RESULT: FAIL (%d expectations failed)" % len(FAILURES))
        return 1
    print("DEMO RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

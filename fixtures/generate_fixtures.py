#!/usr/bin/env python3
"""Regenerate the fixture data files deterministically.

Author: Gavin Blacklock

Run from the code directory: python3 fixtures/generate_fixtures.py
All timestamps, ids, and hashes are fixed inputs, so regeneration is
byte-stable. The fixture secret is a published test secret, not a
real key: fixtures/test_secret.txt.
"""

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.dirname(HERE)
sys.path.insert(0, CODE_DIR)

from acta import GENESIS_HASH, HmacSigner, assemble_receipt, build_receipt, sha256_hex  # noqa: E402
from acta.receipts import payload_dict  # noqa: E402
from acta.signing import b64decode, b64encode  # noqa: E402
from institutio import (  # noqa: E402
    build_checkpoint, compute_charter_hash, example_charter, sign_charter,
)

SECRET = open(os.path.join(HERE, "test_secret.txt"), "rb").read().strip()
SIGNER = HmacSigner(SECRET, key_id="acta-test-key-1")
CHARTER_SIGNER = HmacSigner(SECRET, key_id="founder-root-key-1")
AGENT = {"id": "agent-operator-1", "model": "model-x", "model_version": "1.0"}
DELEGATOR = "seat-founder"
SCOPE = "tools=[read,write];resources=[repo];ops=[call]"
BASE_TIME = 1763900000


def make_chain():
    receipts = []
    grant = build_receipt(
        SIGNER, "r-0001", "GRANT", 0, BASE_TIME, DELEGATOR, AGENT, SCOPE,
        "grant.delegate", sha256_hex(b"args-grant"), sha256_hex(b"result-grant"),
        GENESIS_HASH,
    )
    receipts.append(grant)
    action = build_receipt(
        SIGNER, "r-0002", "ACTION", 1, BASE_TIME + 60, DELEGATOR, AGENT, SCOPE,
        "repo.write_file", sha256_hex(b"args-write"), sha256_hex(b"result-write"),
        grant["receipt_hash"],
        effects={"artifacts_changed": ["repo/file.txt"]},
    )
    receipts.append(action)
    second = build_receipt(
        SIGNER, "r-0003", "ACTION", 2, BASE_TIME + 120, DELEGATOR, AGENT, SCOPE,
        "repo.read_file", sha256_hex(b"args-read"), sha256_hex(b"result-read"),
        action["receipt_hash"],
    )
    receipts.append(second)
    return receipts


def write_fixture(name, fixture):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(fixture, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("wrote", name)


def main():
    chain = make_chain()

    write_fixture("fixture_01_valid_chain.json", {
        "name": "valid chain",
        "kind": "receipt_bundle",
        "expected_verdict": "valid",
        "bundle": {"bundle_version": "0.1", "receipts": chain},
    })

    tampered = copy.deepcopy(chain)
    tampered[1]["result_hash"] = sha256_hex(b"tampered-result")
    write_fixture("fixture_02_tampered_receipt.json", {
        "name": "tampered receipt",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TAMPERED",
        "bundle": {"bundle_version": "0.1", "receipts": tampered},
    })

    reordered = [chain[0], chain[2], chain[1]]
    write_fixture("fixture_03_reordered_chain.json", {
        "name": "reordered chain",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "REORDERED",
        "bundle": {"bundle_version": "0.1", "receipts": reordered},
    })

    bad_denial_payload = {
        "receipt_version": "0.1",
        "receipt_id": "r-bad-denial",
        "receipt_type": "DENIAL",
        "sequence": 1,
        "timestamp": BASE_TIME + 60,
        "delegator": DELEGATOR,
        "agent": AGENT,
        "scope_granted": SCOPE,
        "action": {"name": "repo.write_file",
                   "arguments_hash": sha256_hex(b"args-denied")},
        "result_hash": sha256_hex(b""),
        "effects": {"artifacts_changed": [], "external_calls": [],
                    "sub_delegations": []},
        "prior_receipt_hash": chain[0]["receipt_hash"],
    }
    bad_denial = assemble_receipt(bad_denial_payload, SIGNER)
    write_fixture("fixture_04_denial_without_reason_code.json", {
        "name": "denial without a reason code",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "DENIAL_REASON_MISSING",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0], bad_denial]},
    })

    charter = example_charter()
    charter["authority_manifests"].append({
        "manifest_id": "m-operator-helper-wide",
        "grantor_seat": "operator",
        "grantee_seat": "helper",
        "parent_manifest_id": "m-founder-operator",
        "scope": {
            "tools": ["read", "write", "exec"],
            "resources": ["repo"],
            "operations": ["call"],
            "limits": {"external_calls": 2, "spend_units": 10},
        },
        "issued_at": BASE_TIME + 200,
        "expires_at": BASE_TIME + 300000,
        "sub_delegation_allowed": False,
    })
    write_fixture("fixture_05_child_delegation_exceeds_parent.json", {
        "name": "child delegation exceeding its parent",
        "kind": "charter",
        "expected_verdict": "invalid",
        "expected_error_contains": "exceeds parent",
        "charter": sign_charter(charter, CHARTER_SIGNER),
    })

    replay_chain = make_chain()
    grant = replay_chain[0]
    denial = build_receipt(
        SIGNER, "r-0004", "DENIAL", 3, BASE_TIME + 180, DELEGATOR, AGENT, SCOPE,
        "repo.write_file", sha256_hex(b"args-write"),
        sha256_hex(b""), replay_chain[-1]["receipt_hash"],
        reason_code="revoked",
        verdict={"decision": "deny", "reason_code": "revoked",
                 "detail": "replay of the authorisation in receipt r-0002 "
                           "after the delegation in receipt %s was revoked"
                           % grant["receipt_id"]},
    )
    write_fixture("fixture_06_replayed_authorisation_denial.json", {
        "name": "replayed authorisation attempt recorded as a denial",
        "kind": "receipt_bundle",
        "expected_verdict": "valid",
        "expected_last_receipt": {"receipt_type": "DENIAL",
                                  "reason_code": "revoked"},
        "bundle": {"bundle_version": "0.1",
                   "receipts": replay_chain + [denial]},
    })

    write_fixture("fixture_07_truncated_against_expected_head.json", {
        "name": "truncated chain checked against an expected head",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TRUNCATED",
        "verify_expected_head": chain[-1]["receipt_hash"],
        "bundle": {"bundle_version": "0.1", "receipts": chain[:2]},
    })

    fork = build_receipt(
        SIGNER, "r-fork", "ACTION", 2, BASE_TIME + 120, DELEGATOR, AGENT,
        SCOPE, "repo.write_file", sha256_hex(b"args-fork"),
        sha256_hex(b"result-fork"), chain[0]["receipt_hash"],
    )
    write_fixture("fixture_08_forked_chain.json", {
        "name": "forked chain: a receipt extending the grant, not the head",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "CHAIN_BREAK",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0], chain[1], fork]},
    })

    unknown_payload = {
        "receipt_version": "0.1",
        "receipt_id": "r-unknown-type",
        "receipt_type": "TRANSFER",
        "sequence": 1,
        "timestamp": BASE_TIME + 60,
        "delegator": DELEGATOR,
        "agent": AGENT,
        "scope_granted": SCOPE,
        "action": {"name": "repo.write_file",
                   "arguments_hash": sha256_hex(b"args-unknown")},
        "result_hash": sha256_hex(b"result-unknown"),
        "effects": {"artifacts_changed": [], "external_calls": [],
                    "sub_delegations": []},
        "prior_receipt_hash": chain[0]["receipt_hash"],
    }
    write_fixture("fixture_09_unknown_receipt_type.json", {
        "name": "unknown receipt type must be rejected, not ignored",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "INVALID_RECEIPT",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0], assemble_receipt(unknown_payload,
                                                           SIGNER)]},
    })

    bogus_denial_payload = dict(unknown_payload)
    bogus_denial_payload["receipt_id"] = "r-bogus-denial"
    bogus_denial_payload["receipt_type"] = "DENIAL"
    bogus_denial_payload["reason_code"] = "bogus-code"
    write_fixture("fixture_10_denial_unknown_reason_code.json", {
        "name": "denial with an unknown reason code",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "DENIAL_REASON_MISSING",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0],
                                assemble_receipt(bogus_denial_payload,
                                                 SIGNER)]},
    })

    def standing_receipt(kind, when, name="repo.write", **extra):
        receipt = {
            "receipt_type": kind,
            "timestamp": when,
            "agent": AGENT,
            "action": {"name": name, "scope_class": "write",
                       "risk_weight": 3,
                       "arguments_hash": sha256_hex(b"args-standing")},
            "result_hash": sha256_hex(b"result-standing"),
        }
        receipt.update(extra)
        return receipt

    burn_receipts = [
        standing_receipt("ACTION", BASE_TIME + 60 * i)
        for i in range(6)
    ]
    burn_receipts.append(standing_receipt(
        "DENIAL", BASE_TIME + 600, reason_code="revoked"))
    burn_receipts.append(standing_receipt(
        "BURN", BASE_TIME + 660, name="standing.burn", burn_amount=36))
    write_fixture("fixture_11_burn_to_zero.json", {
        "name": "one severe denial burns an epoch of mint to zero",
        "kind": "standing",
        # Policy stated completely (finding S3): half-life and
        # ceiling curve included, so this fixture now runs as spec
        # conformance in both implementations.
        "standing_policy": {
            "ceiling_curve": [{
                "min_standing": 0, "max_budget_per_action": 100,
                "max_budget_per_epoch": 1000, "max_irreversibility": 3,
                "max_data_sensitivity": 3, "max_delegation_depth": 3,
                "max_fanout": 8}],
            "scope_classes": {"write": {
                "mint_rate": 2, "mint_cap_per_epoch": 36,
                "half_life_seconds": 10000000,
                "hop_attenuation_ppm": 1000000,
                "burn_unit": 36, "burn_multipliers": {"revoked": 1}}}},
        "eval_time": BASE_TIME + 660,
        "agent_id": AGENT["id"],
        "receipts": burn_receipts,
        "expected_standing": {"write": {
            "standing": 0, "minted": 36, "burned": 36,
            "burn_recorded": 36, "denials": 1, "actions": 6}},
    })

    wrong_signer = HmacSigner(SECRET, key_id="rogue-key-9")
    bad_kill = build_receipt(
        wrong_signer, "r-bad-kill", "REVOCATION", 3, BASE_TIME + 240,
        DELEGATOR, AGENT, SCOPE, "delegation.revoke",
        sha256_hex(b"args-revoke"), sha256_hex(b"revoked"),
        chain[-1]["receipt_hash"],
        receipt_extra={"revoked_manifest_id": "m-founder-operator",
                       "revoked_by_key_id": "rogue-key-9"},
    )
    write_fixture("fixture_12_kill_by_wrong_key.json", {
        "name": "a kill attempted by the wrong key is invalid (K4)",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "KEY_ID_MISMATCH",
        "bundle": {"bundle_version": "0.1",
                   "receipts": chain + [bad_kill]},
    })

    noncanonical = copy.deepcopy(chain)
    loose_bytes = json.dumps(
        payload_dict(noncanonical[1]), indent=2).encode("utf-8")
    noncanonical[1]["envelope"]["payload"] = b64encode(loose_bytes)
    write_fixture("fixture_13_noncanonical_envelope.json", {
        "name": "envelope payload in non-canonical encoding is rejected",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TAMPERED",
        "bundle": {"bundle_version": "0.1", "receipts": noncanonical},
    })

    write_fixture("fixture_14_standing_decay_epoch_boundary.json", {
        "name": "Standing decays by whole half-lives across an epoch edge",
        "kind": "standing",
        "standing_policy": {
            "epoch_seconds": 100,
            "ceiling_curve": [{
                "min_standing": 0, "max_budget_per_action": 100,
                "max_budget_per_epoch": 1000, "max_irreversibility": 3,
                "max_data_sensitivity": 3, "max_delegation_depth": 3,
                "max_fanout": 8}],
            "scope_classes": {"write": {
                "mint_rate": 8, "half_life_seconds": 100,
                "hop_attenuation_ppm": 1000000}},
        },
        "eval_time": BASE_TIME + 200,
        "agent_id": AGENT["id"],
        "receipts": [standing_receipt("ACTION", BASE_TIME)],
        "expected_standing": {"write": {
            "standing": 6, "minted": 24, "decay_applied": 18}},
    })

    def denial_fixture(name, filename, reason_code, detail):
        base = make_chain()
        tail = build_receipt(
            SIGNER, "r-deny-" + reason_code, "DENIAL", 3,
            BASE_TIME + 180, DELEGATOR, AGENT, SCOPE,
            "repo.write_file", sha256_hex(b"args-denied-tail"),
            sha256_hex(b""), base[-1]["receipt_hash"],
            reason_code=reason_code,
            verdict={"decision": "deny", "reason_code": reason_code,
                     "detail": detail},
        )
        write_fixture(filename, {
            "name": name,
            "kind": "receipt_bundle",
            "expected_verdict": "valid",
            "expected_last_receipt": {"receipt_type": "DENIAL",
                                      "reason_code": reason_code},
            "bundle": {"bundle_version": "0.1",
                       "receipts": base + [tail]},
        })

    denial_fixture(
        "manifest-mismatch denial: the served tool differs from its pin",
        "fixture_15_manifest_mismatch_denial.json", "manifest-mismatch",
        "tool definition hash differs from the pinned manifest hash")
    denial_fixture(
        "standing-ceiling denial: the call exceeds the recomputed ceiling",
        "fixture_16_standing_ceiling_denial.json", "standing-ceiling",
        "budget per action exceeds the Standing ceiling for the class")

    # Phase 1 expansion (2026-11-23): fixtures 17 to 34 complete the
    # blueprint corpus of 30 enumerated fixtures plus the Provable
    # Kill family K1 to K4. The mapping from blueprint numbers to
    # fixture files, including every analogue and the two uncovered
    # remainders, is recorded in CORPUS-INDEX.md at the programme
    # root. Standing values stated below were computed by hand from
    # specification Section 16.10 and cross-checked against both
    # implementations, as with fixtures 11 and 14.

    expired = example_charter()
    for manifest in expired["authority_manifests"]:
        if manifest["manifest_id"] == "m-operator-helper":
            manifest["expires_at"] = manifest["issued_at"]
    write_fixture("fixture_17_expired_delegation.json", {
        "name": "expired delegation: a manifest expiring at its own issue time",
        "kind": "charter",
        "expected_verdict": "invalid",
        "expected_error_contains": "expires_at must be after issued_at",
        "charter": sign_charter(expired, CHARTER_SIGNER),
    })

    denial_fixture(
        "tool not in the manifest: a scope denial for an unlisted tool",
        "fixture_18_tool_not_in_manifest_denial.json", "scope",
        "tool repo.execute is not in the pinned tool manifest for this seat")

    confused = copy.deepcopy(chain)
    confused[1]["envelope"]["payload_type"] = (
        "application/vnd.acta.receipt.v0.2+json")
    write_fixture("fixture_19_wrong_payload_type.json", {
        "name": "signature envelope with the wrong payload type (type confusion)",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "INVALID_ENVELOPE",
        "bundle": {"bundle_version": "0.1", "receipts": confused},
    })

    truncated_env = copy.deepcopy(chain)
    full_payload = b64decode(truncated_env[1]["envelope"]["payload"])
    truncated_env[1]["envelope"]["payload"] = b64encode(
        full_payload[:len(full_payload) // 2])
    write_fixture("fixture_20_truncated_envelope_payload.json", {
        "name": "truncated envelope payload (PAE length manipulation)",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TAMPERED",
        "bundle": {"bundle_version": "0.1", "receipts": truncated_env},
    })

    write_fixture("fixture_21_replayed_receipt_duplicate_id.json", {
        "name": "replayed receipt: the same receipt presented twice in one chain",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "DUPLICATE_RECEIPT_ID",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0], chain[1],
                                copy.deepcopy(chain[1])]},
    })

    write_fixture("fixture_22_truncated_middle_receipt.json", {
        "name": "truncated chain: the middle receipt is missing (sequence gap)",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "REORDERED",
        "bundle": {"bundle_version": "0.1",
                   "receipts": [chain[0], chain[2]]},
    })

    def complete_write_policy(**extra):
        policy = {
            "ceiling_curve": [{
                "min_standing": 0, "max_budget_per_action": 100,
                "max_budget_per_epoch": 1000, "max_irreversibility": 3,
                "max_data_sensitivity": 3, "max_delegation_depth": 3,
                "max_fanout": 8}],
            "scope_classes": {"write": {
                "mint_rate": 2, "mint_cap_per_epoch": 36,
                "half_life_seconds": 10000000,
                "hop_attenuation_ppm": 1000000,
                "burn_unit": 36, "burn_multipliers": {"revoked": 1}}}}
        policy.update(extra)
        return policy

    write_fixture("fixture_23_standing_mint_cap_saturation.json", {
        "name": "Standing mint saturates at the epoch cap and never above it",
        "kind": "standing",
        "standing_policy": complete_write_policy(),
        "eval_time": BASE_TIME + 540,
        "agent_id": AGENT["id"],
        "receipts": [
            standing_receipt("ACTION", BASE_TIME + 60 * i)
            for i in range(10)
        ],
        "expected_standing": {"write": {
            "standing": 36, "minted": 36, "actions": 10}},
    })

    missing_cs = standing_receipt("ACTION", BASE_TIME)
    missing_cs["counterparty_id"] = "cp-1"
    write_fixture("fixture_24_countersignature_missing_no_mint.json", {
        "name": "a mint whose counterparty countersignature is missing mints nothing",
        "kind": "standing",
        "standing_policy": complete_write_policy(
            countersign_policy={"required_for": ["write"]}),
        "eval_time": BASE_TIME,
        "agent_id": AGENT["id"],
        "receipts": [missing_cs],
        "expected_standing": {"write": {
            "standing": 0, "minted": 0, "actions": 1}},
    })

    witness_ids = ["w-1", "w-2", "w-3", "w-4", "w-5"]
    checkpoint_policy = complete_write_policy(
        witness_policy={"witness_key_ids": witness_ids, "quorum": 3})
    checkpoint_policy["scope_classes"]["write"]["mint_cap_per_epoch"] = 360
    checkpoint_receipts = [
        standing_receipt("ACTION", BASE_TIME + 60 * i) for i in range(3)
    ]
    issuer = HmacSigner(SECRET, key_id="checkpoint-issuer-1")

    def witness_signer(key_id):
        return HmacSigner(SECRET, key_id=key_id)

    def checkpoint_fixture(filename, name, verdict, signers, receipts,
                           needle=None):
        checkpoint = build_checkpoint(
            checkpoint_receipts, checkpoint_policy,
            eval_time=BASE_TIME + 120, agent_id=AGENT["id"],
            org_id="org-example-0001", charter_hash="c" * 64,
            witness_signers=tuple(witness_signer(k) for k in signers),
            checkpoint_signer=issuer)
        fixture = {
            "name": name,
            "kind": "checkpoint",
            "expected_verdict": verdict,
            "standing_policy": checkpoint_policy,
            "receipts": receipts,
            "checkpoint": checkpoint,
        }
        if needle:
            fixture["expected_error_contains"] = needle
        write_fixture(filename, fixture)

    checkpoint_fixture(
        "fixture_25_checkpoint_witness_below_quorum.json",
        "checkpoint with 2 of 5 witness cosignatures, below the quorum of 3",
        "invalid", ["w-1", "w-2"], checkpoint_receipts,
        needle="witness quorum not met")
    checkpoint_fixture(
        "fixture_26_checkpoint_witness_quorum_met.json",
        "checkpoint with 3 of 5 witness cosignatures, meeting the quorum of 3",
        "valid", ["w-1", "w-2", "w-3"], checkpoint_receipts)

    other_receipts = [
        standing_receipt("ACTION", BASE_TIME + 60 * i,
                         name="repo.read")
        for i in range(2)
    ]
    checkpoint_fixture(
        "fixture_27_checkpoint_head_of_other_chain.json",
        "checkpoint whose chain head binds a different chain (anchor for another hash)",
        "invalid", ["w-1", "w-2", "w-3"], other_receipts,
        needle="does not match recomputation")

    forked_view = [chain[0], chain[1]]
    write_fixture("fixture_28_split_view_fork_against_expected_head.json", {
        "name": "split view: a forked prefix presented against the anchored head",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TRUNCATED",
        "verify_expected_head": chain[-1]["receipt_hash"],
        "bundle": {"bundle_version": "0.1", "receipts": forked_view},
    })

    founding = sign_charter(example_charter(), CHARTER_SIGNER)
    amendment_doc = example_charter()
    amendment_doc["org"] = dict(amendment_doc["org"],
                                name="Example Firm Renamed")
    amendment_doc["predecessor_charter_hash"] = compute_charter_hash(founding)
    amendment = sign_charter(amendment_doc, CHARTER_SIGNER)
    write_fixture("fixture_29_charter_succession_chain_valid.json", {
        "name": "charter amendment chain: a valid founder-signed succession",
        "kind": "charter_chain",
        "expected_verdict": "valid",
        "charters": [founding, amendment],
    })

    broken_doc = example_charter()
    broken_doc["org"] = dict(broken_doc["org"],
                             name="Example Firm Renamed")
    broken_doc["predecessor_charter_hash"] = "0" * 64
    broken = sign_charter(broken_doc, CHARTER_SIGNER)
    write_fixture("fixture_30_charter_amendment_broken_link.json", {
        "name": "charter amendment with a broken predecessor hash link",
        "kind": "charter_chain",
        "expected_verdict": "invalid",
        "expected_error_contains": "predecessor_charter_hash does not match",
        "charters": [founding, broken],
    })

    halt_chain = make_chain()
    kill_receipt = build_receipt(
        SIGNER, "r-kill-burn", "KILL-BURN", 3, BASE_TIME + 180,
        DELEGATOR, AGENT, SCOPE, "standing.kill-burn",
        sha256_hex(b"args-kill"), sha256_hex(b"result-kill"),
        halt_chain[-1]["receipt_hash"],
        receipt_extra={"killed_agent_ids": [AGENT["id"]]},
    )
    halt_denial = build_receipt(
        SIGNER, "r-after-halt", "DENIAL", 4, BASE_TIME + 240,
        DELEGATOR, AGENT, SCOPE, "repo.write_file",
        sha256_hex(b"args-after-halt"), sha256_hex(b""),
        kill_receipt["receipt_hash"],
        reason_code="revoked",
        verdict={"decision": "deny", "reason_code": "revoked",
                 "detail": "the organisation is halted by the kill "
                           "switch; every seat is suspended"},
    )
    write_fixture("fixture_31_kill_switch_halt_then_denial.json", {
        "name": "kill-switch halt receipt followed by an attempted action, denied",
        "kind": "receipt_bundle",
        "expected_verdict": "valid",
        "expected_last_receipt": {"receipt_type": "DENIAL",
                                  "reason_code": "revoked"},
        "bundle": {"bundle_version": "0.1",
                   "receipts": halt_chain + [kill_receipt, halt_denial]},
    })

    kill_standing_receipts = [
        standing_receipt("ACTION", BASE_TIME),
        standing_receipt("ACTION", BASE_TIME + 60),
        standing_receipt("ACTION", BASE_TIME + 120),
        standing_receipt("KILL-BURN", BASE_TIME + 180,
                         name="standing.kill-burn",
                         killed_agent_ids=[AGENT["id"]]),
        standing_receipt("ACTION", BASE_TIME + 240),
        standing_receipt("ACTION", BASE_TIME + 300),
    ]
    write_fixture("fixture_32_k1_kill_is_absorbing.json", {
        "name": "K1: a kill is absorbing; post-kill actions restore no Standing",
        "kind": "standing",
        "standing_policy": complete_write_policy(),
        "eval_time": BASE_TIME + 300,
        "agent_id": AGENT["id"],
        "receipts": kill_standing_receipts,
        "expected_standing": {"write": {
            "standing": 0, "minted": 18, "actions": 5}},
    })

    kill_chain = make_chain()
    revocation = build_receipt(
        SIGNER, "r-revocation", "REVOCATION", 3, BASE_TIME + 180,
        DELEGATOR, AGENT, SCOPE, "delegation.revoke",
        sha256_hex(b"args-revoke-k2"), sha256_hex(b"revoked"),
        kill_chain[-1]["receipt_hash"],
        receipt_extra={"revoked_manifest_id": "m-founder-operator",
                       "revoked_by_key_id": "founder-root-key-1"},
    )
    replay_denial = build_receipt(
        SIGNER, "r-k2-replay", "DENIAL", 4, BASE_TIME + 240,
        DELEGATOR, AGENT, SCOPE, "repo.write_file",
        sha256_hex(b"args-write"), sha256_hex(b""),
        revocation["receipt_hash"],
        reason_code="revoked",
        verdict={"decision": "deny", "reason_code": "revoked",
                 "detail": "K2: replay of the pre-kill authorisation "
                           "in receipt r-0002 after the revocation at "
                           "sequence 3; stale authority"},
    )
    write_fixture("fixture_33_k2_replay_after_revocation.json", {
        "name": "K2: a killed seat replays a pre-kill authorisation and is denied",
        "kind": "receipt_bundle",
        "expected_verdict": "valid",
        "expected_last_receipt": {"receipt_type": "DENIAL",
                                  "reason_code": "revoked"},
        "bundle": {"bundle_version": "0.1",
                   "receipts": kill_chain + [revocation, replay_denial]},
    })

    full_kill_head = replay_denial["receipt_hash"]
    write_fixture("fixture_34_k3_fork_omitting_kill.json", {
        "name": "K3: a forked chain omitting the kill, checked against the true head",
        "kind": "receipt_bundle",
        "expected_verdict": "invalid",
        "expected_code": "TRUNCATED",
        "verify_expected_head": full_kill_head,
        "bundle": {"bundle_version": "0.1", "receipts": kill_chain},
    })


if __name__ == "__main__":
    main()

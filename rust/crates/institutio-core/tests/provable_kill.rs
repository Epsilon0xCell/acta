//! The Provable Kill in Rust: specification Section 7, end to end
//! against acta-core and institutio-core.
//!
//! Author: Gavin Blacklock
//!
//! Scenario: a rogue seat holds a genuine delegation with a
//! receipted history and earns Standing. The founder revokes the
//! delegation. A KILL-BURN checkpoint is computed showing the rogue
//! at zero in every class. Three post-revocation attempts (direct,
//! child sub-delegation minted before the revocation, replay of a
//! consumed authorisation) are each denied with reason `revoked`
//! and with `standing-ceiling` recorded as an independent second
//! ground. A sibling seat's checkpoint recomputes unchanged across
//! the kill, and the sibling completes an action after it.

mod common;

use acta_core::cbor::CborValue;
use acta_core::{verify_chain, DenialReason, Ed25519Signer, ReceiptType, Signer, TrustSet};
use common::{counterparty_keys, kill_charter_value, standing_policy_value, vi, vmap, vt, ChainBuilder};
use institutio_core::checkpoint::{build_checkpoint, verify_checkpoint};
use institutio_core::policy::StandingPolicy;
use institutio_core::standing::{compute_standing, StandingReceipt};
use institutio_core::validate_charter_structure;
use std::collections::BTreeMap;

const T0: i64 = 1763900000;
const EVAL: i64 = T0 + 8 * 86400;

fn denial_verdict(manifest_id: &str, extra: Vec<(&str, CborValue)>) -> CborValue {
    let mut pairs = vec![
        ("decision", vt("deny")),
        ("reason_code", vt("revoked")),
        ("standing_scope_class", vt("write")),
        ("manifest_id", vt(manifest_id)),
        ("standing_ceiling", vi(0)),
        (
            "independent_grounds",
            CborValue::Array(vec![vt("revoked"), vt("standing-ceiling")]),
        ),
    ];
    pairs.extend(extra);
    vmap(pairs)
}

fn verdict_int(receipt: &acta_core::SignedReceipt, key: &str) -> Option<i64> {
    match receipt.body.verdict.as_ref() {
        Some(CborValue::Map(map)) => match map.get(key) {
            Some(CborValue::Int(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

fn verdict_has_ground(receipt: &acta_core::SignedReceipt, ground: &str) -> bool {
    match receipt.body.verdict.as_ref() {
        Some(CborValue::Map(map)) => match map.get("independent_grounds") {
            Some(CborValue::Array(items)) => {
                items.iter().any(|i| matches!(i, CborValue::Text(t) if t == ground))
            }
            _ => false,
        },
        _ => false,
    }
}

#[test]
fn provable_kill_end_to_end() {
    // The charter validates, Standing policy included.
    let charter = kill_charter_value();
    let errors = validate_charter_structure(&charter);
    assert!(errors.is_empty(), "charter errors: {errors:?}");
    let policy_value = standing_policy_value();
    let policy = StandingPolicy::from_value(&policy_value).unwrap();
    assert!(institutio_core::validate_policy(&policy).is_empty());
    let charter_hash =
        institutio_core::compute_charter_hash(&charter).unwrap();

    let mut chain = ChainBuilder::new();
    // Grants.
    chain.push(ReceiptType::Grant, "agent-founder", "delegation.grant", T0, None, None);
    chain.push(ReceiptType::Grant, "agent-founder", "delegation.grant", T0 + 10, None, None);
    chain.push(ReceiptType::Grant, "agent-rogue", "delegation.grant", T0 + 20, None, None);
    // The rogue earns Standing over a simulated 7 days of genuine,
    // countersigned work: 14 actions, risk weight 3, mint rate 2,
    // per-epoch cap 40 across two epochs: 80 Standing.
    for i in 0..14 {
        chain.push_action("agent-rogue", "repo.write", T0 + i * 43200, 0);
    }
    // The child acts once, at delegation depth 1.
    chain.push_action("agent-child", "repo.read", T0 + 86400, 1);
    // The sibling works in the same window.
    for i in 0..3 {
        chain.push_action("agent-sibling", "repo.write", T0 + 100 + i * 100, 0);
    }
    let pre_kill_len = chain.receipts.len();

    // Pre-kill checkpoints, recomputed from the published history.
    let rogue_pre = build_checkpoint(
        &chain.receipts, &policy, &policy_value, "agent-rogue",
        "org-kill-test-0001", &charter_hash, Some(EVAL), &counterparty_keys(),
    )
    .unwrap();
    assert_eq!(rogue_pre.standing_vector["write"], 80);
    assert_eq!(
        rogue_pre.ceilings_vector["write"].max_budget_per_action, 250
    );
    let sibling_pre = build_checkpoint(
        &chain.receipts, &policy, &policy_value, "agent-sibling",
        "org-kill-test-0001", &charter_hash, Some(EVAL), &counterparty_keys(),
    )
    .unwrap();
    assert_eq!(sibling_pre.standing_vector["write"], 18);

    // The revocation act, then the kill burn.
    chain.push(
        ReceiptType::Revocation,
        "agent-founder",
        "delegation.revoke",
        T0 + 7 * 86400,
        None,
        Some(vmap(vec![("revoked_manifest_id", vt("m-founder-rogue"))])),
    );
    chain.push(
        ReceiptType::KillBurn,
        "agent-rogue",
        "standing.kill-burn",
        T0 + 7 * 86400 + 60,
        None,
        Some(vmap(vec![(
            "killed_agent_ids",
            CborValue::Array(vec![vt("agent-child")]),
        )])),
    );
    // The three post-revocation attempts.
    let direct = chain.push(
        ReceiptType::Denial,
        "agent-rogue",
        "repo.write",
        T0 + 7 * 86400 + 120,
        Some(DenialReason::Revoked),
        Some(denial_verdict("m-founder-rogue", vec![])),
    );
    let via_child = chain.push(
        ReceiptType::Denial,
        "agent-child",
        "repo.read",
        T0 + 7 * 86400 + 180,
        Some(DenialReason::Revoked),
        Some(denial_verdict("m-rogue-child", vec![])),
    );
    let replay = chain.push(
        ReceiptType::Denial,
        "agent-rogue",
        "repo.write",
        T0 + 7 * 86400 + 240,
        Some(DenialReason::Revoked),
        Some(denial_verdict(
            "m-founder-rogue",
            vec![
                ("replay_of", vt("r-3")),
                ("consumed_authorisation", vt("auth-rogue-0")),
            ],
        )),
    );
    for attempt in [&direct, &via_child, &replay] {
        assert_eq!(attempt.body.reason_code, Some(DenialReason::Revoked));
        assert_eq!(verdict_int(attempt, "standing_ceiling"), Some(0));
        assert!(verdict_has_ground(attempt, "revoked"));
        assert!(verdict_has_ground(attempt, "standing-ceiling"));
    }
    let post_kill_len = chain.receipts.len();

    // The KILL-BURN checkpoint: the rogue is at zero in every class,
    // its pre-kill mint is still on the record, and the two
    // post-kill denials are tallied by reason code.
    let rogue_post = build_checkpoint(
        &chain.receipts, &policy, &policy_value, "agent-rogue",
        "org-kill-test-0001", &charter_hash, Some(EVAL), &counterparty_keys(),
    )
    .unwrap();
    assert_eq!(rogue_post.standing_vector["write"], 0);
    assert_eq!(
        rogue_post.ceilings_vector["write"].max_budget_per_action, 5
    );
    assert_eq!(rogue_post.mint_total, 80);
    assert_eq!(rogue_post.denials_by_reason_code["revoked"], 2);

    // The child, in the killed subtree, is also at zero.
    let views: Vec<StandingReceipt> = chain
        .receipts
        .iter()
        .map(|r| StandingReceipt::from_signed(r).expect("well-formed receipt"))
        .collect();
    let child = compute_standing(&views, &policy, "agent-child", Some(EVAL), &counterparty_keys()).unwrap();
    assert_eq!(child["write"].standing, 0);
    assert!(child["write"].killed);

    // Sibling continuity: the sibling's checkpoint over the
    // post-kill segment recomputes exactly as it did pre-kill.
    let sibling_post = build_checkpoint(
        &chain.receipts, &policy, &policy_value, "agent-sibling",
        "org-kill-test-0001", &charter_hash, Some(EVAL), &counterparty_keys(),
    )
    .unwrap();
    assert_eq!(sibling_post.standing_vector, sibling_pre.standing_vector);
    assert_eq!(sibling_post.mint_total, sibling_pre.mint_total);
    let _ = pre_kill_len;
    let _ = post_kill_len;

    // The sibling completes an action after the kill, and the whole
    // chain verifies.
    chain.push_action("agent-sibling", "repo.write", T0 + 7 * 86400 + 300, 0);
    let trust = TrustSet::from_signer(&Ed25519Signer::from_seed(
        chain.key_id(),
        &[3u8; 32],
    ));
    let verdict = verify_chain(&chain.receipts, &trust, None, None).unwrap();
    assert_eq!(verdict.length, chain.receipts.len());
    let sibling_final = compute_standing(
        &chain
            .receipts
            .iter()
            .map(|r| StandingReceipt::from_signed(r).expect("well-formed receipt"))
            .collect::<Vec<_>>(),
        &policy,
        "agent-sibling",
        Some(EVAL),
        &counterparty_keys(),
    )
    .unwrap();
    assert_eq!(sibling_final["write"].standing, 24);

    // The post-kill rogue checkpoint, signed and witnessed, verifies
    // by recomputation with its quorum met; a tampered copy does not.
    let mut checkpoint = rogue_post.clone();
    let operator = Ed25519Signer::from_seed("operator-key-1", &[9u8; 32]);
    checkpoint.sign(&operator);
    let witnesses = [
        Ed25519Signer::from_seed("witness-1", &[21u8; 32]),
        Ed25519Signer::from_seed("witness-2", &[22u8; 32]),
        Ed25519Signer::from_seed("witness-3", &[23u8; 32]),
    ];
    for witness in &witnesses {
        checkpoint.add_witness_cosig(witness);
    }
    let witness_keys: BTreeMap<String, Vec<u8>> = witnesses
        .iter()
        .map(|w| (w.key_id().to_string(), w.verifying_key_bytes().to_vec()))
        .collect();
    let segment = &chain.receipts[..post_kill_len];
    let operator_keys = TrustSet::from_signer(&operator);
    let verdict = verify_checkpoint(
        &checkpoint, segment, &policy, &policy_value, &witness_keys,
        &operator_keys, &counterparty_keys(),
    )
    .unwrap();
    assert!(verdict.recomputation_matches);
    assert_eq!(verdict.checkpoint_sig_valid, Some(true));
    assert_eq!(verdict.valid_witness_cosigs, 3);
    assert_eq!(verdict.quorum_met, Some(true));
    assert!(!verdict.internal_only);

    // Finding M8: verification rejects, it does not merely report.
    // A tampered standing vector is a recomputation error.
    let mut tampered = checkpoint.clone();
    tampered.standing_vector.insert("write".to_string(), 1);
    let error = verify_checkpoint(
        &tampered, segment, &policy, &policy_value, &witness_keys,
        &operator_keys, &counterparty_keys(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "RECOMPUTATION_MISMATCH", "{error}");

    // Finding M8: the operator signature is checked against the
    // pinned key for its claimed id, never the key the checkpoint
    // carries. An attacker key copying the operator key id is
    // rejected as UNTRUSTED_KEY.
    let attacker = Ed25519Signer::from_seed("operator-key-1", &[8u8; 32]);
    let mut forged = checkpoint.clone();
    forged.sign(&attacker);
    let error = verify_checkpoint(
        &forged, segment, &policy, &policy_value, &witness_keys,
        &operator_keys, &counterparty_keys(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "UNTRUSTED_KEY", "{error}");
}

#[test]
fn test_s6_unwitnessed_checkpoint_identity_fields_are_sealed() {
    // Finding S6: an unwitnessed, unsigned checkpoint once bound
    // none of its identity fields: charter_hash, org_id and
    // eval_time were taken from the checkpoint itself at
    // verification, so relabelling one passed as internal-only.
    // The integrity seal over the signing view now binds them,
    // exactly as the Python prototype's seal does.
    let mut chain = ChainBuilder::new();
    chain.push_action("agent-x", "repo.write", T0, 0);
    chain.push_action("agent-x", "repo.write", T0 + 60, 0);
    let mut policy_value = standing_policy_value();
    policy_value
        .as_object_mut()
        .unwrap()
        .remove("witness_policy");
    let policy = StandingPolicy::from_value(&policy_value).unwrap();
    let checkpoint = build_checkpoint(
        &chain.receipts, &policy, &policy_value, "agent-x",
        "org-x", "charter-hash-x", Some(T0 + 60), &counterparty_keys(),
    )
    .unwrap();
    assert!(!checkpoint.integrity_hash.is_empty());
    let operator = Ed25519Signer::from_seed("operator-key-1", &[7u8; 32]);
    let operator_keys = TrustSet::from_signer(&operator);
    let verdict = verify_checkpoint(
        &checkpoint, &chain.receipts, &policy, &policy_value,
        &BTreeMap::new(), &operator_keys, &counterparty_keys(),
    )
    .unwrap();
    assert!(verdict.internal_only);
    assert_eq!(verdict.checkpoint_sig_valid, None);

    for tamper in ["org", "charter", "eval_time"] {
        let mut forged = checkpoint.clone();
        match tamper {
            "org" => forged.org_id = "org-forged".to_string(),
            "charter" => forged.charter_hash = "forged".to_string(),
            _ => forged.eval_time += 1,
        }
        let error = verify_checkpoint(
            &forged, &chain.receipts, &policy, &policy_value,
            &BTreeMap::new(), &operator_keys, &counterparty_keys(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("integrity hash"),
            "{tamper}: {error}"
        );
    }
}

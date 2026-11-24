//! ComputeStanding tests: mint, burn, decay, ceilings, the
//! Section 16.10 diversity caps and policy validations, and the
//! typed errors for values the policy itself omits.
//!
//! Author: Gavin Blacklock

use acta_core::cbor::CborValue;
use acta_core::signing::{hex_encode, sha256};
use acta_core::{
    build_receipt, Agent, DenialReason, Ed25519Signer, Effects, ReceiptDraft, ReceiptType,
    SignedReceipt, GENESIS_HASH,
};
use institutio_core::error::UnspecifiedField;
use institutio_core::policy::StandingPolicy;
use institutio_core::standing::{
    ceilings_for_standing, compute_standing, counterparty_outcome_bytes, countersign_outcome,
    effective_authority, Ceilings, StandingReceipt,
};
use institutio_core::{validate_policy, InstitutioError};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The test counterparty signer (key id `cp-1`).
fn cp_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("cp-1", &[11u8; 32])
}

/// Pinned counterparty verification material for ComputeStanding.
fn cp_keys() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("cp-1".to_string(), cp_signer().verifying_key_bytes().to_vec())])
}

fn receipt(
    receipt_type: ReceiptType,
    timestamp: i64,
    scope_class: &str,
    risk_weight: u64,
    signed: bool,
    reason_code: Option<DenialReason>,
) -> StandingReceipt {
    StandingReceipt {
        receipt_type,
        timestamp,
        agent_id: "agent-1".to_string(),
        action_name: "repo.write".to_string(),
        scope_class: scope_class.to_string(),
        risk_weight,
        counterparty_id: Some("cp-1".to_string()),
        // A real signature over the bound outcome descriptor when
        // `signed` is set (finding N4): presence is not enough.
        counterparty_sig: if signed {
            Some(countersign_outcome(
                &cp_signer(),
                "agent-1",
                "repo.write",
                scope_class,
                timestamp,
                risk_weight,
                None,
                None,
                None,
            ))
        } else {
            None
        },
        receipt_id: None,
        arguments_hash: None,
        result_hash: None,
        delegation_depth: 0,
        reason_code,
        burn_amount: None,
        kill_targets: Vec::new(),
        subtree_root_id: None,
    }
}

fn action(timestamp: i64, scope_class: &str, risk_weight: u64) -> StandingReceipt {
    receipt(ReceiptType::Action, timestamp, scope_class, risk_weight, true, None)
}

fn policy(mut value: Value) -> StandingPolicy {
    // Repair round 4 (Section 16.10, decision 23): producing
    // ceilings is part of ComputeStanding's result, so a policy
    // stating no ceiling curve anywhere is an error in both
    // implementations. Test policies that do not state a curve
    // get the base curve here, stated once; their assertions are
    // unchanged. (The no-curve error itself is tested through
    // StandingPolicy::from_value directly, not through this
    // helper.)
    if let Some(map) = value.as_object_mut() {
        if !map.contains_key("ceiling_curve") {
            map.insert(
                "ceiling_curve".into(),
                json!([
                    {"min_standing": 0, "max_budget_per_action": 5,
                     "max_budget_per_epoch": 25, "max_irreversibility": 0,
                     "max_data_sensitivity": 0, "max_delegation_depth": 0,
                     "max_fanout": 0},
                    {"min_standing": 10, "max_budget_per_action": 50,
                     "max_budget_per_epoch": 250, "max_irreversibility": 1,
                     "max_data_sensitivity": 2, "max_delegation_depth": 1,
                     "max_fanout": 2}
                ]),
            );
        }
    }
    StandingPolicy::from_value(&value).unwrap()
}

fn base_policy() -> StandingPolicy {
    policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "mint_cap_per_epoch": 40,
            "half_life_seconds": 2592000, "hop_attenuation_ppm": 1000000,
            "burn_unit": 10,
            "burn_multipliers": {"revoked": 5, "scope": 5, "budget": 1},
            "severe_reason_codes": ["revoked", "scope"],
            "correlated_burn_fraction_ppm": 250000
        }},
        "ceiling_curve": [
            {"min_standing": 0, "max_budget_per_action": 5,
             "max_budget_per_epoch": 25, "max_irreversibility": 0,
             "max_data_sensitivity": 0, "max_delegation_depth": 0,
             "max_fanout": 0},
            {"min_standing": 10, "max_budget_per_action": 50,
             "max_budget_per_epoch": 250, "max_irreversibility": 1,
             "max_data_sensitivity": 2, "max_delegation_depth": 1,
             "max_fanout": 2}
        ]
    }))
}

#[test]
fn mint_is_risk_weighted_and_capped_per_epoch() {
    let policy = base_policy();
    // 8 actions at mint_rate 2 * risk 3 = 6 each: 48 raw, cap 40.
    let receipts: Vec<StandingReceipt> = (0..8)
        .map(|i| action(1000 + i * 10, "write", 3))
        .collect();
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(1080), &cp_keys()).unwrap();
    let write = &standing["write"];
    assert_eq!(write.minted, 40);
    assert_eq!(write.standing, 40);
    assert_eq!(write.actions, 8);
}

#[test]
fn countersign_required_means_unsigned_mints_zero() {
    let value = json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 1000000
        }},
        "countersign_policy": {"required_for": ["write"]},
        "ceiling_curve": [
            {"min_standing": 0, "max_budget_per_action": 5,
             "max_budget_per_epoch": 25, "max_irreversibility": 0,
             "max_data_sensitivity": 0, "max_delegation_depth": 0,
             "max_fanout": 0},
            {"min_standing": 10, "max_budget_per_action": 50,
             "max_budget_per_epoch": 250, "max_irreversibility": 1,
             "max_data_sensitivity": 2, "max_delegation_depth": 1,
             "max_fanout": 2}
        ]
    });
    let policy = StandingPolicy::from_value(&value).unwrap();
    let unsigned = vec![receipt(ReceiptType::Action, 1000, "write", 3, false, None)];
    let standing = compute_standing(&unsigned, &policy, "agent-1", Some(1000), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 0);
    let signed = vec![action(1000, "write", 3)];
    let standing = compute_standing(&signed, &policy, "agent-1", Some(1000), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 6);
}

#[test]
fn burn_is_super_linear_in_the_denial_ordinal() {
    let mut receipts: Vec<StandingReceipt> = (0..20)
        .map(|i| action(1000 + i * 10, "write", 1))
        .collect();
    // Mint is capped at 40 for the epoch; use a second policy with
    // no cap for the burn arithmetic check.
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 10, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 1000000,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 2},
            "severe_reason_codes": ["revoked"],
            "correlated_burn_fraction_ppm": 0
        }}
    }));
    receipts.push(receipt(
        ReceiptType::Denial, 2000, "write", 0, true, Some(DenialReason::Revoked),
    ));
    receipts.push(receipt(
        ReceiptType::Denial, 2010, "write", 0, true, Some(DenialReason::Revoked),
    ));
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(2010), &cp_keys()).unwrap();
    let write = &standing["write"];
    assert_eq!(write.minted, 200);
    // First denial burns 5 * 2 * 1 * 1 = 10; the second burns
    // 5 * 2 * 2 * 2 = 40. Total 50, super-linear in the ordinal.
    assert_eq!(write.burned, 50);
    assert_eq!(write.standing, 150);
    assert_eq!(write.denials, 2);
}

#[test]
fn severe_denial_burns_correlated_classes() {
    let policy = policy(json!({
        "scope_classes": {
            "write": {
                "mint_rate": 10, "half_life_seconds": 2592000,
                "hop_attenuation_ppm": 1000000,
                "burn_unit": 10,
                "burn_multipliers": {"revoked": 4},
                "severe_reason_codes": ["revoked"],
                "correlated_burn_fraction_ppm": 250000
            },
            "read": {
                "mint_rate": 10, "half_life_seconds": 2592000,
                "hop_attenuation_ppm": 1000000
            }
        }
    }));
    let mut receipts = vec![action(1000, "read", 4), action(1010, "write", 4)];
    receipts.push(receipt(
        ReceiptType::Denial, 2000, "write", 0, true, Some(DenialReason::Revoked),
    ));
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(2000), &cp_keys()).unwrap();
    // Write burn: 10 * 4 * 1 * 1 = 40. Correlated: 25% of 40 = 10
    // burned in read, which minted 40 and keeps 30.
    assert_eq!(standing["write"].burned, 40);
    assert_eq!(standing["read"].burned, 10);
    assert_eq!(standing["read"].standing, 30);
}

#[test]
fn decay_is_whole_half_lives_per_mint_event() {
    // The same arithmetic the prototype's fixture 14 states,
    // reached here through the specification function: mint 24 at
    // t, evaluate two half-lives later, 6 remains.
    let policy = policy(json!({
        "epoch_seconds": 100,
        "scope_classes": {"write": {
            "mint_rate": 8, "half_life_seconds": 100,
            "hop_attenuation_ppm": 1000000
        }}
    }));
    let receipts = vec![action(1763900000, "write", 3)];
    let standing =
        compute_standing(&receipts, &policy, "agent-1", Some(1763900200), &cp_keys()).unwrap();
    let write = &standing["write"];
    assert_eq!(write.minted, 24);
    assert_eq!(write.decay_applied, 18);
    assert_eq!(write.standing, 6);
}

#[test]
fn hop_attenuation_scales_mint_by_depth() {
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 8, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 500000
        }}
    }));
    let mut deep = action(1000, "write", 1);
    deep.delegation_depth = 2;
    let standing = compute_standing(&[deep], &policy, "agent-1", Some(1000), &cp_keys()).unwrap();
    // 8 * (1/2)^2 = 2.
    assert_eq!(standing["write"].minted, 2);
}

#[test]
fn kill_burn_zeroes_and_later_actions_mint_nothing() {
    let policy = base_policy();
    let mut receipts: Vec<StandingReceipt> = (0..4)
        .map(|i| action(1000 + i * 10, "write", 3))
        .collect();
    let mut kill = receipt(ReceiptType::KillBurn, 2000, "write", 0, true, None);
    kill.action_name = "standing.kill-burn".to_string();
    receipts.push(kill);
    receipts.push(action(3000, "write", 3));
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(3000), &cp_keys()).unwrap();
    let write = &standing["write"];
    assert!(write.killed);
    assert_eq!(write.standing, 0);
    assert_eq!(write.minted, 24);
    assert_eq!(write.actions, 5);
}

#[test]
fn new_agent_starts_at_zero() {
    let policy = base_policy();
    let receipts = vec![action(1000, "write", 3)];
    let standing = compute_standing(&receipts, &policy, "agent-nobody", Some(1000), &cp_keys()).unwrap();
    assert!(standing.is_empty());
}

#[test]
fn missing_burn_unit_is_unspecified_not_invented() {
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 1000000,
            "burn_multipliers": {"revoked": 5}
        }}
    }));
    let receipts = vec![receipt(
        ReceiptType::Denial, 1000, "write", 0, true, Some(DenialReason::Revoked),
    )];
    let error = compute_standing(&receipts, &policy, "agent-1", Some(1000), &cp_keys()).unwrap_err();
    assert_eq!(
        error,
        InstitutioError::UnspecifiedBySpec(UnspecifiedField::BurnUnit)
    );
}

#[test]
fn ceilings_bind_and_effective_authority_is_the_minimum() {
    let policy = base_policy();
    let ceilings = ceilings_for_standing(&policy, "write", 40, 0).unwrap();
    assert_eq!(ceilings.max_budget_per_action, 50);
    let grant = Ceilings {
        max_budget_per_action: 250,
        max_budget_per_epoch: 1000,
        max_irreversibility: 2,
        max_data_sensitivity: 3,
        max_delegation_depth: 2,
        max_fanout: 4,
    };
    let manifest = Ceilings {
        max_budget_per_action: 100,
        max_budget_per_epoch: 500,
        max_irreversibility: 1,
        max_data_sensitivity: 2,
        max_delegation_depth: 1,
        max_fanout: 2,
    };
    let effective = effective_authority(&grant, &manifest, &ceilings);
    assert_eq!(effective.max_budget_per_action, 50);
    assert_eq!(effective.max_budget_per_epoch, 250);
    assert_eq!(effective.max_irreversibility, 1);
    assert_eq!(effective.max_delegation_depth, 1);

    let no_curve = StandingPolicy::from_value(&json!({
        "scope_classes": {"write": {"mint_rate": 1, "half_life_seconds": 100}}
    }))
    .unwrap();
    let error = ceilings_for_standing(&no_curve, "write", 0, 0).unwrap_err();
    assert_eq!(
        error,
        InstitutioError::UnspecifiedBySpec(UnspecifiedField::CeilingCurve)
    );
}

#[test]
fn diversity_fraction_cap_is_a_fraction_of_the_epoch_mint_cap() {
    // Section 16.10, decision 8: the counterparty fraction cap is
    // floor(mint_cap_per_epoch * ppm / 1,000,000). Cap 40 at
    // 250,000 ppm gives a per-counterparty cap of 10 per epoch.
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "mint_cap_per_epoch": 40,
            "half_life_seconds": 2592000, "hop_attenuation_ppm": 1000000
        }},
        "diversity_caps": {"per_counterparty_fraction_ppm": 250000}
    }));
    // All receipts name the same counterparty (cp-1 in the helper):
    // raw mint 6 each, so the counterparty cap binds at 10.
    let receipts: Vec<StandingReceipt> = (0..5)
        .map(|i| action(1000 + i * 10, "write", 3))
        .collect();
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(1080), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 10);
}

#[test]
fn diversity_subtree_fraction_cap_keys_by_subtree_root() {
    // Section 16.10, decision 8: the subtree cap is keyed by the
    // receipt's subtree_root_id. Cap 40 at 500,000 ppm gives 20 per
    // subtree per epoch; two subtrees mint 20 each.
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "mint_cap_per_epoch": 40,
            "half_life_seconds": 2592000, "hop_attenuation_ppm": 1000000
        }},
        "diversity_caps": {"per_subtree_fraction_ppm": 500000}
    }));
    let mut receipts: Vec<StandingReceipt> = Vec::new();
    for i in 0..5 {
        let mut r = action(1000 + i * 10, "write", 3);
        r.subtree_root_id = Some("child-a".to_string());
        receipts.push(r);
    }
    for i in 0..5 {
        let mut r = action(2000 + i * 10, "write", 3);
        r.subtree_root_id = Some("child-b".to_string());
        receipts.push(r);
    }
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(2080), &cp_keys()).unwrap();
    // Each subtree raw-mints 30, capped at 20: total 40, which is
    // also the epoch mint cap.
    assert_eq!(standing["write"].minted, 40);
}

#[test]
fn policy_validation_rejects_zero_epoch_and_out_of_range_inheritance() {
    // Section 16.10, decisions 3 and 13.
    let bad_epoch = policy(json!({
        "epoch_seconds": 0,
        "scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 100,
            "hop_attenuation_ppm": 1000000
        }}
    }));
    let errors = validate_policy(&bad_epoch);
    assert!(errors.iter().any(|e| e.contains("epoch_seconds")), "{errors:?}");
    let bad_inheritance = policy(json!({
        "inheritance_factor_ppm": 1000000,
        "scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 100,
            "hop_attenuation_ppm": 1000000
        }}
    }));
    let errors = validate_policy(&bad_inheritance);
    assert!(
        errors.iter().any(|e| e.contains("inheritance_factor_ppm")),
        "{errors:?}"
    );
}

#[test]
fn policy_validation_enforces_the_severe_floor() {
    let weak = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "mint_cap_per_epoch": 100,
            "half_life_seconds": 2592000, "hop_attenuation_ppm": 1000000,
            "burn_unit": 5,
            "burn_multipliers": {"revoked": 1},
            "severe_reason_codes": ["revoked"]
        }}
    }));
    let errors = validate_policy(&weak);
    assert!(
        errors.iter().any(|e| e.contains("invariant I5")),
        "{errors:?}"
    );
    let strong = base_policy();
    assert!(validate_policy(&strong).is_empty());
}

#[test]
fn test_n4_garbage_countersignature_mints_zero() {
    // Finding N4: countersigning is cryptographic. A garbage
    // signature value, present in the field, mints nothing where
    // the policy requires a countersignature.
    let value = json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 1000000
        }},
        "countersign_policy": {"required_for": ["write"]},
        "ceiling_curve": [
            {"min_standing": 0, "max_budget_per_action": 5,
             "max_budget_per_epoch": 25, "max_irreversibility": 0,
             "max_data_sensitivity": 0, "max_delegation_depth": 0,
             "max_fanout": 0},
            {"min_standing": 10, "max_budget_per_action": 50,
             "max_budget_per_epoch": 250, "max_irreversibility": 1,
             "max_data_sensitivity": 2, "max_delegation_depth": 1,
             "max_fanout": 2}
        ]
    });
    let policy = StandingPolicy::from_value(&value).unwrap();
    let mut forged = action(1000, "write", 3);
    forged.counterparty_sig = Some(vec![7u8; 64]);
    let standing = compute_standing(&[forged], &policy, "agent-1", Some(1000), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 0);
}

#[test]
fn test_n4_replayed_and_reweighted_countersignatures_mint_zero() {
    // A signature made for one receipt does not transfer to
    // another timestamp, and does not survive a risk-weight change
    // (the descriptor binds both, finding M2 mirrored under N4).
    let value = json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": 2592000,
            "hop_attenuation_ppm": 1000000
        }},
        "countersign_policy": {"required_for": ["write"]},
        "ceiling_curve": [
            {"min_standing": 0, "max_budget_per_action": 5,
             "max_budget_per_epoch": 25, "max_irreversibility": 0,
             "max_data_sensitivity": 0, "max_delegation_depth": 0,
             "max_fanout": 0},
            {"min_standing": 10, "max_budget_per_action": 50,
             "max_budget_per_epoch": 250, "max_irreversibility": 1,
             "max_data_sensitivity": 2, "max_delegation_depth": 1,
             "max_fanout": 2}
        ]
    });
    let policy = StandingPolicy::from_value(&value).unwrap();
    let genuine = action(1000, "write", 3);
    let mut replayed = action(2000, "write", 3);
    replayed.counterparty_sig = genuine.counterparty_sig.clone();
    let standing =
        compute_standing(&[replayed], &policy, "agent-1", Some(2000), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 0);
    let mut reweighted = action(1000, "write", 3);
    reweighted.counterparty_sig = Some(countersign_outcome(
        &cp_signer(),
        "agent-1",
        "repo.write",
        "write",
        1000,
        1,
        None,
        None,
        None,
    ));
    let standing =
        compute_standing(&[reweighted], &policy, "agent-1", Some(1000), &cp_keys()).unwrap();
    assert_eq!(standing["write"].minted, 0);
    // Without the pinned key, even the genuine signature mints zero.
    let standing = compute_standing(
        &[genuine],
        &policy,
        "agent-1",
        Some(1000),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(standing["write"].minted, 0);
}

#[test]
fn test_n3_zero_half_life_is_error_not_panic() {
    // Finding N3: compute_standing validates its policy inputs; a
    // zero half-life is a PolicyInvalid error, never a divide by
    // zero.
    let policy = policy(json!({
        "scope_classes": {"write": {
            "mint_rate": 2, "half_life_seconds": 0,
            "hop_attenuation_ppm": 1000000
        }}
    }));
    let receipts = vec![action(1000, "write", 3)];
    let error = compute_standing(&receipts, &policy, "agent-1", Some(1000), &cp_keys())
        .unwrap_err();
    assert!(
        matches!(error, InstitutioError::PolicyInvalid(_)),
        "{error:?}"
    );
}

#[test]
fn test_r9_correlated_burn_reaches_later_touched_class() {
    // Section 16.10, decision 7: correlated classes are every other
    // class with a receipt in the segment, including one first
    // touched after the severe denial.
    let policy = policy(json!({
        "scope_classes": {
            "write": {
                "mint_rate": 10, "half_life_seconds": 2592000,
                "hop_attenuation_ppm": 1000000,
                "burn_unit": 10,
                "burn_multipliers": {"revoked": 4},
                "severe_reason_codes": ["revoked"],
                "correlated_burn_fraction_ppm": 250000
            },
            "read": {
                "mint_rate": 10, "half_life_seconds": 2592000,
                "hop_attenuation_ppm": 1000000
            }
        }
    }));
    let mut receipts = vec![action(1000, "write", 4)];
    receipts.push(receipt(
        ReceiptType::Denial, 1500, "write", 0, true, Some(DenialReason::Revoked),
    ));
    receipts.push(action(2000, "read", 4));
    let standing = compute_standing(&receipts, &policy, "agent-1", Some(2000), &cp_keys()).unwrap();
    // Severe burn 40 in write; correlated 10 lands in read even
    // though read's first receipt is after the denial.
    assert_eq!(standing["read"].burned, 10);
    assert_eq!(standing["read"].standing, 30);
}


// -----------------------------------------------------------------
// Repair round 3 (second re-audit findings S1 to S6, minors s1
// and s5): composition. Each test is named for its finding and
// encodes the re-audit's attack.
// -----------------------------------------------------------------

#[test]
fn test_s1_descriptor_bytes_are_exactly_the_specified_form() {
    // Section 16.10 decision 16 fixes the descriptor: canonical
    // JSON of exactly these eight fields, absent fields null. The
    // pre-repair bytes carried the action name under the key
    // "action", so a Python countersignature could never verify
    // here (finding S1).
    let bytes = counterparty_outcome_bytes(
        "agent-1", "tool.call", "write", 100, 3,
        Some("r-1"), None, None,
    );
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"action_name\":\"tool.call\",\"agent_id\":\"agent-1\",\
         \"arguments_hash\":null,\"receipt_id\":\"r-1\",\
         \"result_hash\":null,\"risk_weight\":3,\
         \"scope_class\":\"write\",\"timestamp\":100}"
            .replace(" ", "")
    );
}

fn signed_receipt_with_verdict(verdict: CborValue) -> SignedReceipt {
    let signer = Ed25519Signer::from_seed("gate-key-1", &[3u8; 32]);
    let draft = ReceiptDraft {
        receipt_id: "r-0".to_string(),
        receipt_type: ReceiptType::Action,
        sequence: 0,
        timestamp: 1000,
        delegator: "founder".to_string(),
        agent: Agent {
            id: "agent-1".to_string(),
            model: "model-x".to_string(),
            model_version: "1.0".to_string(),
        },
        scope_granted: "write".to_string(),
        action_name: "repo.write".to_string(),
        arguments_hash: hex_encode(&sha256(b"args-0")),
        result_hash: hex_encode(&sha256(b"result-0")),
        prior_receipt_hash: GENESIS_HASH.to_string(),
        effects: Effects::default(),
        reason_code: None,
        verdict: Some(verdict),
    };
    build_receipt(&signer, signer.verifying_key_bytes().to_vec(), draft)
        .expect("test receipt builds")
}

#[test]
fn test_s2_negative_verdict_integers_are_parse_errors() {
    // Finding S2: from_signed once clamped a negative delegation
    // depth to 0, silently granting full unattenuated mint. Every
    // out-of-range verdict integer is a parse error now.
    let verdict_with = |key: &str, value: i64| {
        let mut map = BTreeMap::new();
        map.insert("standing_scope_class".to_string(), CborValue::Text("write".to_string()));
        map.insert(key.to_string(), CborValue::Int(value));
        CborValue::Map(map)
    };
    for key in ["delegation_depth", "risk_weight", "burn_amount"] {
        let signed = signed_receipt_with_verdict(verdict_with(key, -1));
        let error = StandingReceipt::from_signed(&signed).unwrap_err();
        assert!(
            error.to_string().contains("negative"),
            "{key}: {error}"
        );
    }
    // And the non-negative form still parses.
    let signed = signed_receipt_with_verdict(verdict_with("delegation_depth", 2));
    let view = StandingReceipt::from_signed(&signed).unwrap();
    assert_eq!(view.delegation_depth, 2);
}

#[test]
fn test_s3_missing_burn_unit_is_unspecified_not_defaulted() {
    // Finding S3, Rust twin: the policy states no burn_unit, a
    // denial arrives, and the computation stops with the typed
    // error rather than reaching for any default.
    let policy = StandingPolicy::from_value(&json!({
        "ceiling_curve": [{
            "min_standing": 0, "max_budget_per_action": 100,
            "max_budget_per_epoch": 1000, "max_irreversibility": 3,
            "max_data_sensitivity": 3, "max_delegation_depth": 3,
            "max_fanout": 8
        }],
        "scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 10000000,
            "burn_multipliers": {"budget": 1}
        }}
    }))
    .unwrap();
    let receipts = vec![
        receipt(ReceiptType::Action, 10, "write", 1, false, None),
        receipt(
            ReceiptType::Denial, 20, "write", 0, false,
            Some(DenialReason::Budget),
        ),
    ];
    let error = compute_standing(&receipts, &policy, "agent-1", Some(20), &cp_keys())
        .unwrap_err();
    assert_eq!(
        error,
        InstitutioError::UnspecifiedBySpec(UnspecifiedField::BurnUnit)
    );
}

#[test]
fn test_s4_prototype_kill_names_its_child() {
    // Finding S4: the prototype path once hardcoded an empty kill
    // list, so a KILL-BURN naming a child in killed_agent_ids
    // computed the child at full Standing here and zero in the
    // Python tree. One field name, honoured in every path.
    let kill = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "KILL-BURN",
        "timestamp": 20,
        "agent": {"id": "agent-parent"},
        "action": {"name": "standing.kill-burn", "scope_class": "write"},
        "killed_agent_ids": ["agent-child"]
    }))
    .unwrap();
    assert_eq!(kill.kill_targets, vec!["agent-child".to_string()]);

    let policy = StandingPolicy::from_value(&json!({
        "ceiling_curve": [{
            "min_standing": 0, "max_budget_per_action": 100,
            "max_budget_per_epoch": 1000, "max_irreversibility": 3,
            "max_data_sensitivity": 3, "max_delegation_depth": 3,
            "max_fanout": 8
        }],
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 1000000,
            "half_life_seconds": 10000000, "hop_attenuation_ppm": 1000000
        }}
    }))
    .unwrap();
    let action = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "ACTION",
        "timestamp": 10,
        "agent": {"id": "agent-child"},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": 10}
    }))
    .unwrap();
    let standing = compute_standing(
        &[action, kill], &policy, "agent-child", Some(20), &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(standing["write"].standing, 0);
    assert!(standing["write"].killed);
}

#[test]
fn test_s5_epoch_seconds_zero_is_a_policy_error() {
    // Minor s5: decision 3 makes an epoch length of 0 an error,
    // never a synonym for absent. (Named for re-audit minor s5;
    // finding S5 is the witness quorum, covered in the Python
    // tree's test_repair_round3.py.)
    let policy = StandingPolicy::from_value(&json!({
        "epoch_seconds": 0,
        "scope_classes": {"write": {"mint_rate": 1}}
    }))
    .unwrap();
    let receipts = vec![receipt(
        ReceiptType::Action, 10, "write", 1, false, None,
    )];
    let error = compute_standing(&receipts, &policy, "agent-1", Some(10), &cp_keys())
        .unwrap_err();
    assert!(
        matches!(error, InstitutioError::PolicyInvalid(_)),
        "{error}"
    );
}

#[test]
fn test_diversity_caps_per_class_placement_is_a_parse_error() {
    // Section 16.10 decision 18: caps live at policy level only.
    let error = StandingPolicy::from_value(&json!({
        "scope_classes": {"write": {
            "mint_rate": 1,
            "diversity_caps": {"per_counterparty_fraction_ppm": 500000}
        }}
    }))
    .unwrap_err();
    assert!(
        error.to_string().contains("decision 18"),
        "{error}"
    );
}

#[test]
fn test_t1_countersign_policy_other_forms_are_parse_errors() {
    // Third re-audit finding T1 (repair round 4): decision 22
    // fixes ONE encoding for the countersign requirement. Every
    // other shape is a policy validation error, never silently
    // honoured and never silently ignored. Pre-repair this tree
    // accepted four sub-forms of countersign_policy and ignored
    // the Python tree's countersign_required entirely.
    let class = json!({"mint_rate": 1, "half_life_seconds": 100});
    for value in [
        // A bare boolean.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": true}),
        // A bare array.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": ["write"]}),
        // A different inner key.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": {"classes": ["write"]}}),
        // A per-class boolean map.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": {"write": true}}),
        // An extra key beside required_for.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": {"required_for": ["write"], "classes": []}}),
        // A non-string entry.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_policy": {"required_for": [1]}}),
        // The differently named field, policy level.
        json!({"scope_classes": {"write": class.clone()},
               "countersign_required": true}),
        // The differently named field, inside a class.
        json!({"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 100,
            "countersign_required": true}}}),
        // The spec field name, inside a class.
        json!({"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 100,
            "countersign_policy": {"required_for": ["write"]}}}}),
    ] {
        let error = StandingPolicy::from_value(&value).unwrap_err();
        assert!(
            matches!(error, InstitutioError::PolicyInvalid(_)),
            "{value}: {error}"
        );
    }
    // The one conforming form parses, and only it.
    let parsed = StandingPolicy::from_value(&json!({
        "scope_classes": {"write": class.clone()},
        "countersign_policy": {"required_for": ["write"]}
    }))
    .unwrap();
    assert!(parsed.countersign_required.contains("write"));
}

#[test]
fn test_t2_duplicate_receipt_id_rejected_at_computation() {
    // Third re-audit finding T2 (repair round 4): a prototype
    // segment with two receipts sharing one receipt_id minted on
    // both (Standing 20) pre-repair. Decision 19 makes receipt
    // identities unique; the Python computation raises on the
    // same segment.
    let policy = base_policy();
    let first = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "ACTION", "timestamp": 1000,
        "receipt_id": "dup",
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": 10, "delegation_depth": 0}
    }))
    .unwrap();
    let second = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "ACTION", "timestamp": 1010,
        "receipt_id": "dup",
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": 10, "delegation_depth": 0}
    }))
    .unwrap();
    let error = compute_standing(
        &[first, second],
        &policy,
        "agent-1",
        Some(1010),
        &cp_keys(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("DUPLICATE_RECEIPT_ID"), "{error}");
}

#[test]
fn test_t4_missing_ceiling_curve_is_a_computation_error() {
    // Third re-audit minor t4 (repair round 4): decision 23
    // makes the ceiling curve a required field wherever ceilings
    // are produced, and ComputeStanding produces them (Section
    // 16.1). Pre-repair this tree returned a Standing of 10 for
    // this policy where the Python tree errored.
    let policy = StandingPolicy::from_value(&json!({
        "scope_classes": {"write": {
            "mint_rate": 1, "mint_cap_per_epoch": 40,
            "half_life_seconds": 2592000, "hop_attenuation_ppm": 1000000
        }}
    }))
    .unwrap();
    let receipts = vec![action(1000, "write", 10)];
    let error = compute_standing(&receipts, &policy, "agent-1", Some(1000), &cp_keys())
        .unwrap_err();
    assert_eq!(
        error,
        InstitutioError::UnspecifiedBySpec(UnspecifiedField::CeilingCurve)
    );
}

#[test]
fn test_t5_negative_burn_amount_is_a_parse_error() {
    // Third re-audit minor t5 (repair round 4): a present
    // burn_amount of minus 5 was silently dropped to none on the
    // prototype path (the tally read 0 where the Python tree
    // tallied minus 5). Both trees now reject it.
    let error = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "BURN", "timestamp": 1000,
        "agent": {"id": "agent-1"},
        "action": {"name": "standing.burn", "scope_class": "write",
                   "burn_amount": -5}
    }))
    .unwrap_err();
    assert!(error.to_string().contains("burn_amount"), "{error}");
}

#[test]
fn test_t6_malformed_witness_policy_is_a_parse_error() {
    // Third re-audit minor t6 (repair round 4): decision 15
    // admits exactly {witness_key_ids, quorum}. Pre-repair the
    // parser accepted a "k" alias for quorum and defaulted a
    // missing quorum to 0.
    let class = json!({"mint_rate": 1, "half_life_seconds": 100});
    for witness in [
        json!({"witness_key_ids": ["w-1"], "k": 1}),
        json!({"witness_key_ids": ["w-1"]}),
        json!({"witness_key_ids": ["w-1"], "quorum": "1"}),
        json!({"witness_key_ids": ["w-1"], "quorum": 1, "extra": 0}),
        json!({"witness_key_ids": [7], "quorum": 1}),
        json!({"quorum": 1}),
    ] {
        let error = StandingPolicy::from_value(&json!({
            "scope_classes": {"write": class.clone()},
            "witness_policy": witness
        }))
        .unwrap_err();
        assert!(
            matches!(error, InstitutioError::PolicyInvalid(_)),
            "{witness}: {error}"
        );
    }
    // Decision 15's bounds are a validation error: quorum 0 and
    // a quorum above the witness count both fail validate_policy.
    for (witness, _) in [
        (json!({"witness_key_ids": ["w-1"], "quorum": 0}), ()),
        (json!({"witness_key_ids": ["w-1"], "quorum": 2}), ()),
    ] {
        let parsed = StandingPolicy::from_value(&json!({
            "scope_classes": {"write": class.clone()},
            "witness_policy": witness
        }))
        .unwrap();
        let errors = validate_policy(&parsed);
        assert!(
            errors.iter().any(|e| e.contains("witness_policy quorum")),
            "{errors:?}"
        );
    }
}

#[test]
fn test_u3_null_policy_fields_are_parse_errors() {
    // Fourth re-audit finding U3 (repair round 5, Section 16.10
    // decision 24 row (c)): this parser read a stated null class
    // field as absent while the Python parser errored. A stated
    // null is malformed for every field, in both trees.
    let class = json!({"mint_rate": 1, "half_life_seconds": 100});
    for (field, bad_class) in [
        ("mint_cap_per_epoch", json!({"mint_rate": 1, "mint_cap_per_epoch": null})),
        ("hop_attenuation_ppm", json!({"mint_rate": 1, "hop_attenuation_ppm": null})),
        ("correlated_burn_fraction_ppm", json!({"mint_rate": 1, "correlated_burn_fraction_ppm": null})),
        ("burn_multipliers", json!({"mint_rate": 1, "burn_multipliers": null})),
        ("severe_reason_codes", json!({"mint_rate": 1, "severe_reason_codes": null})),
        ("ceiling_curve", json!({"mint_rate": 1, "ceiling_curve": null})),
    ] {
        let error = StandingPolicy::from_value(&json!({
            "scope_classes": {"write": bad_class}
        }))
        .unwrap_err();
        assert!(
            matches!(error, InstitutioError::PolicyInvalid(_)),
            "{field}: {error}"
        );
    }
    for (field, bad_policy) in [
        ("epoch_seconds", json!({"scope_classes": {"write": class.clone()}, "epoch_seconds": null})),
        ("countersign_policy", json!({"scope_classes": {"write": class.clone()}, "countersign_policy": null})),
        ("witness_policy", json!({"scope_classes": {"write": class.clone()}, "witness_policy": null})),
        ("diversity_caps", json!({"scope_classes": {"write": class.clone()}, "diversity_caps": null})),
        ("scope class itself", json!({"scope_classes": {"write": null}})),
    ] {
        assert!(
            StandingPolicy::from_value(&bad_policy).is_err(),
            "{field} stated as null must be a parse error"
        );
    }
}

#[test]
fn test_u3_null_risk_weight_is_a_parse_error() {
    // Fourth re-audit S2 residue (repair round 5): an explicit
    // null risk_weight was read as absent (default 1, Standing
    // computed) by this prototype parser while Python errored.
    let error = StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "ACTION", "timestamp": 100,
        "agent": {"id": "agent-1"},
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": null}
    }))
    .unwrap_err();
    assert!(error.to_string().contains("risk_weight"), "{error}");
    // The same for a stated null burn_amount (decision 24 (c)).
    assert!(StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "BURN", "timestamp": 100,
        "agent": {"id": "agent-1"},
        "action": {"name": "standing.burn", "scope_class": "write",
                   "burn_amount": null}
    }))
    .is_err());
}

#[test]
fn test_u4_severe_codes_alias_rejected() {
    // Fourth re-audit finding U4 (repair round 5, decision 24
    // row (d)): this parser honoured the undocumented
    // severe_codes alias, silently dropping non-string entries,
    // while the Python parser read only severe_reason_codes.
    let error = StandingPolicy::from_value(&json!({
        "scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": 100,
            "severe_codes": ["budget"]
        }}
    }))
    .unwrap_err();
    assert!(
        error.to_string().contains("severe_reason_codes"),
        "{error}"
    );
}

#[test]
fn test_u5_malformed_timestamps_are_parse_errors() {
    // Fourth re-audit finding U5 (repair round 5): a float
    // timestamp of 100.9 and a string timestamp of "100" mapped
    // to 0 here and computed Standing 0 with full decay, where
    // Python coerced both to 100. Both trees now reject them,
    // and negative and null timestamps with them.
    for bad in [json!(100.9), json!("100"), json!(-5), json!(null), json!(true)] {
        let error = StandingReceipt::from_prototype_json(&json!({
            "receipt_type": "ACTION", "timestamp": bad,
            "agent": {"id": "agent-1"},
            "action": {"name": "tool.call", "scope_class": "write",
                       "risk_weight": 1}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("timestamp"), "{bad}: {error}");
    }
}

#[test]
fn test_t2_nonstring_receipt_id_is_a_parse_error() {
    // Fourth re-audit T2 residue (repair round 5): two prototype
    // receipts both carrying receipt_id 123 (a JSON number)
    // computed Standing 20 here, both identities silently erased
    // at parse, where Python raised on the duplicate. A
    // non-string identity is malformed, never erased.
    for bad_id in [json!(123), json!(null), json!(true)] {
        let error = StandingReceipt::from_prototype_json(&json!({
            "receipt_type": "ACTION", "timestamp": 100,
            "receipt_id": bad_id,
            "agent": {"id": "agent-1"},
            "action": {"name": "tool.call", "scope_class": "write",
                       "risk_weight": 1}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("receipt_id"), "{bad_id}: {error}");
    }
}

#[test]
fn test_s5_witness_quorum_bounds_checked_at_computation() {
    // Fourth re-audit S5 residue (repair round 5, decision 24
    // row (e)): quorum bounds were checked in validate_policy
    // and at checkpoint verification but not in the computation,
    // so a caller who only computed got a different policy. The
    // computation now refuses quorum 0 and an over-large quorum
    // at entry, as the Python computation does.
    let class = json!({"mint_rate": 1, "mint_cap_per_epoch": 40,
                       "half_life_seconds": 2592000,
                       "hop_attenuation_ppm": 1000000});
    for quorum in [0, 2] {
        let parsed = policy(json!({
            "scope_classes": {"write": class.clone()},
            "witness_policy": {"witness_key_ids": ["w-1"], "quorum": quorum}
        }));
        let receipts = vec![action(1000, "write", 10)];
        let error = compute_standing(&receipts, &parsed, "agent-1", Some(1000), &cp_keys())
            .unwrap_err();
        assert!(
            error.to_string().contains("witness_policy quorum"),
            "quorum {quorum}: {error}"
        );
    }
}

#[test]
fn test_w5_agent_as_string_is_a_parse_error() {
    // Fifth re-audit finding W5 (repair round 6): an agent
    // stated as a bare string was validated by neither tree:
    // Python crashed with an AttributeError and this parser
    // read the id as absent and computed an empty result. The
    // agent field is the specification's agent object; any
    // other stated shape is a parse error here and a
    // validation error in Python.
    for bad_agent in [json!("agent-1"), json!(7), json!(null), json!(["agent-1"])] {
        let error = StandingReceipt::from_prototype_json(&json!({
            "receipt_type": "ACTION", "timestamp": 100,
            "agent": bad_agent,
            "action": {"name": "tool.call", "scope_class": "write",
                       "risk_weight": 1}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("agent"), "{bad_agent}: {error}");
    }
    // An absent agent field remains absence, as before.
    assert!(StandingReceipt::from_prototype_json(&json!({
        "receipt_type": "ACTION", "timestamp": 100,
        "action": {"name": "tool.call", "scope_class": "write",
                   "risk_weight": 1}
    }))
    .is_ok());
}

#[test]
fn test_w3_tier_missing_a_field_is_a_parse_error() {
    // Fifth re-audit finding W3 (repair round 6): decision 10
    // fixes the ceiling tier's field set (min_standing plus
    // the six ceiling outputs), and this parser has always
    // required all seven integer fields. The test pins the
    // rule the Python validator now matches: it once checked
    // only the fields present, so a tier missing max_fanout
    // computed there and was refused here.
    for missing in ["min_standing", "max_budget_per_action",
                    "max_budget_per_epoch", "max_irreversibility",
                    "max_data_sensitivity", "max_delegation_depth",
                    "max_fanout"] {
        let mut tier = json!({
            "min_standing": 0, "max_budget_per_action": 5,
            "max_budget_per_epoch": 25, "max_irreversibility": 0,
            "max_data_sensitivity": 0, "max_delegation_depth": 0,
            "max_fanout": 0
        });
        tier.as_object_mut().unwrap().remove(missing);
        let error = StandingPolicy::from_value(&json!({
            "ceiling_curve": [tier],
            "scope_classes": {"write": {
                "mint_rate": 1, "half_life_seconds": 100}}
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains(missing),
            "tier missing {missing}: {error}"
        );
    }
}

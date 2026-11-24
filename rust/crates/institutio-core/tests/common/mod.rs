//! Shared test support: the kill-test charter and standing policy,
//! and a chain builder over acta-core.
//!
//! Author: Gavin Blacklock

use acta_core::cbor::CborValue;
use acta_core::signing::{hex_encode, sha256};
use acta_core::{
    build_receipt, Agent, DenialReason, Ed25519Signer, Effects, ReceiptDraft, ReceiptType,
    SignedReceipt, GENESIS_HASH,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The complete standing policy of the kill test. Every parameter
/// the computation needs is stated here, in the policy, because
/// that is where Section 16 puts them.
pub fn standing_policy_value() -> Value {
    json!({
        "standing_policy_version": "0.1",
        "epoch_seconds": 604800,
        "scope_classes": {
            "write": {
                "mint_rate": 2,
                "mint_cap_per_epoch": 40,
                "half_life_seconds": 2592000,
                "hop_attenuation_ppm": 1000000,
                "burn_unit": 10,
                "burn_multipliers": {
                    "revoked": 5,
                    "scope": 5,
                    "manifest-mismatch": 2,
                    "budget": 1,
                    "standing-ceiling": 2
                },
                "severe_reason_codes": ["revoked", "scope"],
                "correlated_burn_fraction_ppm": 250000
            }
        },
        "countersign_policy": {"required_for": ["write"]},
        "ceiling_curve": [
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
             "max_fanout": 4}
        ],
        "witness_policy": {
            "witness_key_ids": ["witness-1", "witness-2", "witness-3"],
            "quorum": 2
        }
    })
}

/// The kill-test charter: founder, rogue, child, and sibling seats;
/// the rogue holds a sub-delegable manifest and a child beneath it.
pub fn kill_charter_value() -> Value {
    let mut charter = json!({
        "charter_version": "0.1",
        "org": {
            "name": "Kill Test Firm",
            "charter_id": "org-kill-test-0001",
            "founded": "2026-11-23",
            "founder_key_id": "founder-root-key-1"
        },
        "seats": [
            {"seat_id": "founder", "title": "Founder", "role": "root",
             "occupant_key_id": "founder-root-key-1", "reports_to": null,
             "scope": {"tools": ["read", "write", "exec"],
                       "resources": ["repo", "ledger"],
                       "operations": ["call", "delegate", "revoke"],
                       "limits": {"external_calls": 100, "spend_units": 1000}}},
            {"seat_id": "rogue", "title": "Rogue", "role": "worker",
             "occupant_key_id": "rogue-key-1", "reports_to": "founder",
             "scope": {"tools": ["read", "write"],
                       "resources": ["repo"],
                       "operations": ["call", "delegate"],
                       "limits": {"external_calls": 10, "spend_units": 100}}},
            {"seat_id": "child", "title": "Child", "role": "worker",
             "occupant_key_id": "child-key-1", "reports_to": "rogue",
             "scope": {"tools": ["read"],
                       "resources": ["repo"],
                       "operations": ["call"],
                       "limits": {"external_calls": 2, "spend_units": 10}}},
            {"seat_id": "sibling", "title": "Sibling", "role": "worker",
             "occupant_key_id": "sibling-key-1", "reports_to": "founder",
             "scope": {"tools": ["read", "write"],
                       "resources": ["repo"],
                       "operations": ["call"],
                       "limits": {"external_calls": 10, "spend_units": 100}}}
        ],
        "authority_manifests": [
            {"manifest_id": "m-founder-rogue",
             "grantor_seat": "founder", "grantee_seat": "rogue",
             "scope": {"tools": ["read", "write"],
                       "resources": ["repo"],
                       "operations": ["call", "delegate"],
                       "limits": {"external_calls": 10, "spend_units": 100}},
             "issued_at": 1763900000, "expires_at": 1766500000,
             "sub_delegation_allowed": true, "budget_ref": "b-rogue"},
            {"manifest_id": "m-rogue-child",
             "grantor_seat": "rogue", "grantee_seat": "child",
             "parent_manifest_id": "m-founder-rogue",
             "scope": {"tools": ["read"],
                       "resources": ["repo"],
                       "operations": ["call"],
                       "limits": {"external_calls": 2, "spend_units": 10}},
             "issued_at": 1763900100, "expires_at": 1766500000,
             "sub_delegation_allowed": false},
            {"manifest_id": "m-founder-sibling",
             "grantor_seat": "founder", "grantee_seat": "sibling",
             "scope": {"tools": ["read", "write"],
                       "resources": ["repo"],
                       "operations": ["call"],
                       "limits": {"external_calls": 10, "spend_units": 100}},
             "issued_at": 1763900000, "expires_at": 1766500000,
             "sub_delegation_allowed": false, "budget_ref": "b-sibling"}
        ],
        "budgets": [
            {"budget_id": "b-rogue", "seat_id": "rogue", "amount": 100,
             "unit": "spend_units", "period": "day", "on_limit": "refuse"},
            {"budget_id": "b-sibling", "seat_id": "sibling", "amount": 100,
             "unit": "spend_units", "period": "day", "on_limit": "refuse"}
        ],
        "amendment": {"authorized_key_ids": ["founder-root-key-1"],
                      "notice_period_seconds": 86400,
                      "frozen_fields": ["kill_switch"]},
        "succession": [
            {"seat": "founder", "successor_seat": "sibling",
             "trigger": "signed_succession_act"}
        ],
        "kill_switch": {"authorized_key_ids": ["founder-root-key-1"],
                        "recovery_seat": "founder"},
        "anchoring": {"mechanisms": ["rfc3161", "transparency-log"]}
    });
    charter["standing_policy"] = standing_policy_value();
    charter
}

/// A CBOR text value.
pub fn vt(text: &str) -> CborValue {
    CborValue::Text(text.to_string())
}

/// A CBOR integer value.
pub fn vi(number: i64) -> CborValue {
    CborValue::Int(number)
}

/// A CBOR map from key and value pairs.
pub fn vmap(pairs: Vec<(&str, CborValue)>) -> CborValue {
    let map: BTreeMap<String, CborValue> = pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    CborValue::Map(map)
}

/// The test counterparty signer (key id `cp-1`).
pub fn counterparty_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("cp-1", &[11u8; 32])
}

/// The pinned counterparty verification material for
/// ComputeStanding: counterparty id to 32-byte verifying key.
pub fn counterparty_keys() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(
        "cp-1".to_string(),
        counterparty_signer().verifying_key_bytes().to_vec(),
    )])
}

/// Builds a signed native chain receipt by receipt.
pub struct ChainBuilder {
    signer: Ed25519Signer,
    /// The receipts built so far, in chain order.
    pub receipts: Vec<SignedReceipt>,
}

impl ChainBuilder {
    /// A builder signing with the gate key.
    pub fn new() -> Self {
        ChainBuilder {
            signer: Ed25519Signer::from_seed("gate-key-1", &[3u8; 32]),
            receipts: Vec::new(),
        }
    }

    /// The signing key identifier.
    pub fn key_id(&self) -> &str {
        "gate-key-1"
    }

    /// Append one receipt and return it.
    pub fn push(
        &mut self,
        receipt_type: ReceiptType,
        agent_id: &str,
        action_name: &str,
        timestamp: i64,
        reason_code: Option<DenialReason>,
        verdict: Option<CborValue>,
    ) -> SignedReceipt {
        let sequence = self.receipts.len() as u64;
        let prior = self
            .receipts
            .last()
            .map(|r| r.receipt_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let draft = ReceiptDraft {
            receipt_id: format!("r-{sequence}"),
            receipt_type,
            sequence,
            timestamp,
            delegator: "founder".to_string(),
            agent: Agent {
                id: agent_id.to_string(),
                model: "model-x".to_string(),
                model_version: "1.0".to_string(),
            },
            scope_granted: "write".to_string(),
            action_name: action_name.to_string(),
            arguments_hash: hex_encode(&sha256(format!("args-{sequence}").as_bytes())),
            result_hash: hex_encode(&sha256(format!("result-{sequence}").as_bytes())),
            prior_receipt_hash: prior,
            effects: Effects::default(),
            reason_code,
            verdict,
        };
        let signed = build_receipt(&self.signer, self.signer.verifying_key_bytes().to_vec(), draft)
            .expect("test receipts build");
        self.receipts.push(signed.clone());
        signed
    }

    /// Append one minting ACTION receipt whose counterparty
    /// countersignature is a real Ed25519 signature over the bound
    /// outcome descriptor of the receipt being built (finding N4).
    /// The receipt id and hashes are the deterministic values
    /// `push` will assign, so the descriptor names this receipt.
    pub fn push_action(
        &mut self,
        agent_id: &str,
        action_name: &str,
        timestamp: i64,
        depth: i64,
    ) -> SignedReceipt {
        let sequence = self.receipts.len() as u64;
        let receipt_id = format!("r-{sequence}");
        let arguments_hash = hex_encode(&sha256(format!("args-{sequence}").as_bytes()));
        let result_hash = hex_encode(&sha256(format!("result-{sequence}").as_bytes()));
        let signature = institutio_core::countersign_outcome(
            &counterparty_signer(),
            agent_id,
            action_name,
            "write",
            timestamp,
            3,
            Some(&receipt_id),
            Some(&arguments_hash),
            Some(&result_hash),
        );
        let verdict = vmap(vec![
            ("standing_scope_class", vt("write")),
            ("risk_weight", vi(3)),
            ("counterparty_id", vt("cp-1")),
            ("counterparty_sig", CborValue::Bytes(signature)),
            ("delegation_depth", vi(depth)),
        ]);
        self.push(
            ReceiptType::Action,
            agent_id,
            action_name,
            timestamp,
            None,
            Some(verdict),
        )
    }
}

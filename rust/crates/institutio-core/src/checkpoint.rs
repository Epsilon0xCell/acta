//! The `StandingCheckpoint` object: the portable unit a third
//! party reads (specification Section 16.3), its signing and
//! witness cosigning, and the stranger's verification procedure of
//! Section 16.7 in code.
//!
//! Author: Gavin Blacklock
//!
//! A checkpoint is a claim about a computation, not an authority in
//! itself. Verification recomputes Standing from the chain head the
//! checkpoint names and rejects the checkpoint when recomputation
//! differs. Cosignatures follow invariant I8: k-of-n independent
//! witnesses on the Sigsum and Certificate Transparency pattern.
//! An unwitnessed checkpoint is valid for internal use and is
//! labelled as such by [`CheckpointVerdict::internal_only`].
//!
//! Rejection, not just reporting (re-audit finding M8):
//! [`verify_checkpoint`] returns an error when recomputation
//! differs, when a present operator signature does not verify
//! under the PINNED key for its claimed key id (the key carried
//! inside the checkpoint is never believed), or when the policy's
//! witness quorum is unmet. The verdict struct is returned only
//! for a checkpoint that passes.

use crate::error::{InstitutioError, Result, UnspecifiedField};
use crate::policy::StandingPolicy;
use crate::standing::{compute_standing, Ceilings, StandingReceipt};
use acta_core::cbor::{self, CborValue};
use acta_core::legacy::canonical_json_bytes;
use acta_core::receipt::SignatureEntry;
use acta_core::signing::{hex_encode, sha256, verify_ed25519, verifying_key_from_bytes};
use acta_core::{chain_head, Ed25519Signer, SignedReceipt, Signer, TrustSet};
use serde_json::Value;
use std::collections::BTreeMap;

/// DSSE payload type for Standing checkpoints.
pub const CHECKPOINT_PAYLOAD_TYPE: &str =
    "application/vnd.institutio.standing-checkpoint.v0.1+cbor";

/// A Standing checkpoint, field for field as Section 16.3 names
/// them, including the `eval_time` field Section 16.10, decision 5,
/// added to that object: decay makes a checkpoint without an
/// evaluation time unrecomputable, so the field is normative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingCheckpoint {
    /// Agent the checkpoint is about.
    pub agent_id: String,
    /// Organisation identifier.
    pub org_id: String,
    /// Hash of the charter in force.
    pub charter_hash: String,
    /// Hash of the `standing_policy` in force.
    pub standing_policy_hash: String,
    /// Hash of the last receipt the computation ran over.
    pub receipt_chain_head_hash: String,
    /// Epoch of the evaluation time under the policy.
    pub epoch: i64,
    /// Evaluation time the computation ran at, integer seconds.
    pub eval_time: i64,
    /// Standing per scope class.
    pub standing_vector: BTreeMap<String, u64>,
    /// Ceilings per scope class.
    pub ceilings_vector: BTreeMap<String, Ceilings>,
    /// Total minted before decay, all classes.
    pub mint_total: u64,
    /// Total burned, all classes.
    pub burn_total: u64,
    /// Total decay applied, all classes.
    pub decay_applied: u64,
    /// Denials by reason code (wire strings), all classes.
    pub denials_by_reason_code: BTreeMap<String, u64>,
    /// Witness cosignatures over the checkpoint signing bytes.
    pub witness_cosigs: Vec<SignatureEntry>,
    /// The operator's signature over the checkpoint signing bytes.
    pub checkpoint_sig: Option<SignatureEntry>,
    /// Tamper-evident seal over the checkpoint's core fields:
    /// hex SHA-256 of the signing view, which covers agent_id,
    /// org_id, charter_hash, standing_policy_hash,
    /// receipt_chain_head_hash, epoch, eval_time, and every
    /// computed vector and total (repair round 3, finding S6).
    /// Verified in [`verify_checkpoint`] even for unwitnessed and
    /// unsigned checkpoints, matching the Python prototype's
    /// integrity value: before this field existed, the identity
    /// fields of an unwitnessed checkpoint were bound by nothing
    /// at all, and a relabelled checkpoint passed as internal-only.
    pub integrity_hash: String,
}

/// The hash of a `standing_policy` JSON value: SHA-256 over its
/// canonical JSON bytes, the same canonical form charters use.
pub fn standing_policy_hash(policy_value: &Value) -> Result<String> {
    let bytes = canonical_json_bytes(policy_value)?;
    Ok(hex_encode(&sha256(&bytes)))
}

fn ceilings_to_cbor(ceilings: &Ceilings) -> CborValue {
    let mut map = BTreeMap::new();
    let int = |n: u64| CborValue::Int(n as i64);
    map.insert("max_budget_per_action".into(), int(ceilings.max_budget_per_action));
    map.insert("max_budget_per_epoch".into(), int(ceilings.max_budget_per_epoch));
    map.insert("max_irreversibility".into(), int(ceilings.max_irreversibility));
    map.insert("max_data_sensitivity".into(), int(ceilings.max_data_sensitivity));
    map.insert("max_delegation_depth".into(), int(ceilings.max_delegation_depth));
    map.insert("max_fanout".into(), int(ceilings.max_fanout));
    CborValue::Map(map)
}

impl StandingCheckpoint {
    /// The checkpoint as a deterministic CBOR value, with the
    /// signature fields cleared when `for_signing` is set: the
    /// signing view is the checkpoint with no `checkpoint_sig` and
    /// no witness cosignatures, so the operator and every witness
    /// sign identical bytes.
    pub fn to_cbor(&self, for_signing: bool) -> CborValue {
        let text = |s: &str| CborValue::Text(s.to_string());
        let mut map = BTreeMap::new();
        map.insert("agent_id".into(), text(&self.agent_id));
        map.insert("org_id".into(), text(&self.org_id));
        map.insert("charter_hash".into(), text(&self.charter_hash));
        map.insert(
            "standing_policy_hash".into(),
            text(&self.standing_policy_hash),
        );
        map.insert(
            "receipt_chain_head_hash".into(),
            text(&self.receipt_chain_head_hash),
        );
        map.insert("epoch".into(), CborValue::Int(self.epoch));
        map.insert("eval_time".into(), CborValue::Int(self.eval_time));
        let standing: BTreeMap<String, CborValue> = self
            .standing_vector
            .iter()
            .map(|(k, v)| (k.clone(), CborValue::Int(*v as i64)))
            .collect();
        map.insert("standing_vector".into(), CborValue::Map(standing));
        let ceilings: BTreeMap<String, CborValue> = self
            .ceilings_vector
            .iter()
            .map(|(k, v)| (k.clone(), ceilings_to_cbor(v)))
            .collect();
        map.insert("ceilings_vector".into(), CborValue::Map(ceilings));
        map.insert("mint_total".into(), CborValue::Int(self.mint_total as i64));
        map.insert("burn_total".into(), CborValue::Int(self.burn_total as i64));
        map.insert(
            "decay_applied".into(),
            CborValue::Int(self.decay_applied as i64),
        );
        let denials: BTreeMap<String, CborValue> = self
            .denials_by_reason_code
            .iter()
            .map(|(k, v)| (k.clone(), CborValue::Int(*v as i64)))
            .collect();
        map.insert("denials_by_reason_code".into(), CborValue::Map(denials));
        if !for_signing {
            // The seal itself is not part of the signing view, so
            // signing and witnessing never change the sealed bytes.
            map.insert("integrity_hash".into(), text(&self.integrity_hash));
        }
        if !for_signing {
            let cosigs: Vec<CborValue> = self
                .witness_cosigs
                .iter()
                .map(|entry| {
                    let mut entry_map = BTreeMap::new();
                    entry_map.insert("key_id".into(), text(&entry.key_id));
                    entry_map.insert(
                        "signature".into(),
                        CborValue::Bytes(entry.signature.clone()),
                    );
                    entry_map.insert(
                        "verifying_key".into(),
                        CborValue::Bytes(entry.verifying_key.clone()),
                    );
                    CborValue::Map(entry_map)
                })
                .collect();
            map.insert("witness_cosigs".into(), CborValue::Array(cosigs));
        }
        CborValue::Map(map)
    }

    /// Canonical deterministic CBOR bytes of the signing view.
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_cbor(true))
    }

    /// The integrity seal this checkpoint's contents should carry:
    /// hex SHA-256 over the signing view (finding S6).
    pub fn compute_integrity_hash(&self) -> String {
        hex_encode(&sha256(&self.signing_bytes()))
    }

    /// Sign the checkpoint as its operator.
    pub fn sign(&mut self, signer: &Ed25519Signer) {
        let signature = signer.sign_pae(CHECKPOINT_PAYLOAD_TYPE, &self.signing_bytes());
        self.checkpoint_sig = Some(SignatureEntry {
            key_id: signer.key_id().to_string(),
            signature,
            verifying_key: signer.verifying_key_bytes().to_vec(),
        });
    }

    /// Add one witness cosignature over the signing bytes.
    pub fn add_witness_cosig(&mut self, witness: &Ed25519Signer) {
        let signature = witness.sign_pae(CHECKPOINT_PAYLOAD_TYPE, &self.signing_bytes());
        self.witness_cosigs.push(SignatureEntry {
            key_id: witness.key_id().to_string(),
            signature,
            verifying_key: witness.verifying_key_bytes().to_vec(),
        });
    }
}

/// Build a checkpoint by running ComputeStanding over a signed
/// chain segment. Fails with
/// [`InstitutioError::UnspecifiedBySpec`] when the policy carries
/// no ceiling curve: a checkpoint without ceilings is not the
/// object Section 16.3 defines.
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint(
    receipts: &[SignedReceipt],
    policy: &StandingPolicy,
    policy_value: &Value,
    agent_id: &str,
    org_id: &str,
    charter_hash: &str,
    eval_time: Option<i64>,
    counterparty_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<StandingCheckpoint> {
    if policy.ceiling_curve.is_none()
        && !policy
            .scope_classes
            .values()
            .any(|c| c.ceiling_curve.is_some())
    {
        return Err(InstitutioError::UnspecifiedBySpec(
            UnspecifiedField::CeilingCurve,
        ));
    }
    let views: Vec<StandingReceipt> = receipts
        .iter()
        .map(StandingReceipt::from_signed)
        .collect::<Result<Vec<_>>>()?;
    let eval = eval_time.unwrap_or_else(|| views.iter().map(|r| r.timestamp).max().unwrap_or(0));
    let standing = compute_standing(&views, policy, agent_id, Some(eval), counterparty_keys)?;
    let mut denials_by_reason_code: BTreeMap<String, u64> = BTreeMap::new();
    for receipt in &views {
        if receipt.agent_id == agent_id {
            if let Some(code) = receipt.reason_code {
                *denials_by_reason_code
                    .entry(code.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }
    }
    let mut checkpoint = StandingCheckpoint {
        agent_id: agent_id.to_string(),
        org_id: org_id.to_string(),
        charter_hash: charter_hash.to_string(),
        standing_policy_hash: standing_policy_hash(policy_value)?,
        receipt_chain_head_hash: chain_head(receipts),
        epoch: policy.epoch_of(eval),
        eval_time: eval,
        standing_vector: standing
            .iter()
            .map(|(k, v)| (k.clone(), v.standing))
            .collect(),
        ceilings_vector: standing
            .iter()
            .filter_map(|(k, v)| v.ceilings.map(|c| (k.clone(), c)))
            .collect(),
        mint_total: standing.values().map(|v| v.minted).sum(),
        burn_total: standing.values().map(|v| v.burned).sum(),
        decay_applied: standing.values().map(|v| v.decay_applied).sum(),
        denials_by_reason_code,
        witness_cosigs: Vec::new(),
        checkpoint_sig: None,
        integrity_hash: String::new(),
    };
    checkpoint.integrity_hash = checkpoint.compute_integrity_hash();
    Ok(checkpoint)
}

/// Outcome of verifying a checkpoint by recomputation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointVerdict {
    /// Recomputation from the named chain head reproduces the
    /// checkpoint's vectors and totals exactly.
    pub recomputation_matches: bool,
    /// The operator signature verifies, when one is present.
    pub checkpoint_sig_valid: Option<bool>,
    /// Witness cosignatures that verify against the named witness
    /// keys and the policy's witness list.
    pub valid_witness_cosigs: usize,
    /// The policy quorum is met, when the policy names witnesses.
    pub quorum_met: Option<bool>,
    /// True when the checkpoint carries no witness cosignatures:
    /// valid for internal use only, and labelled as such (I8).
    pub internal_only: bool,
}

/// Verify a checkpoint the stranger's way (Section 16.7):
/// recompute Standing from the chain segment the checkpoint names
/// and compare every carried value; verify the operator signature
/// against the pinned `operator_keys` trust set; verify witness
/// cosignatures against `witness_keys` (key identifier to 32-byte
/// verifying key) and count them against the policy's quorum.
///
/// This is a rejecting check (finding M8): any failure is an
/// `Err`, and the verdict is returned only for a checkpoint that
/// passes every applicable check. An absent operator signature is
/// not a failure (the verdict reports `checkpoint_sig_valid:
/// None`); a present one that names an unpinned key, carries a
/// key differing from the pinned key, or does not verify, is.
pub fn verify_checkpoint(
    checkpoint: &StandingCheckpoint,
    receipts: &[SignedReceipt],
    policy: &StandingPolicy,
    policy_value: &Value,
    witness_keys: &BTreeMap<String, Vec<u8>>,
    operator_keys: &TrustSet,
    counterparty_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<CheckpointVerdict> {
    // The tamper-evident seal first (finding S6): it binds the
    // identity fields (charter_hash, org_id, eval_time, and the
    // rest of the signing view) even when the checkpoint is
    // unwitnessed and unsigned, the case recomputation alone
    // cannot catch because recomputation takes those fields from
    // the checkpoint itself.
    if checkpoint.integrity_hash != checkpoint.compute_integrity_hash() {
        return Err(InstitutioError::RecomputationMismatch(
            "checkpoint integrity hash does not match its contents \
             (tamper-evident seal, finding S6)"
                .into(),
        ));
    }
    let recomputed = build_checkpoint(
        receipts,
        policy,
        policy_value,
        &checkpoint.agent_id,
        &checkpoint.org_id,
        &checkpoint.charter_hash,
        Some(checkpoint.eval_time),
        counterparty_keys,
    )?;
    let recomputation_matches = recomputed.standing_vector == checkpoint.standing_vector
        && recomputed.ceilings_vector == checkpoint.ceilings_vector
        && recomputed.mint_total == checkpoint.mint_total
        && recomputed.burn_total == checkpoint.burn_total
        && recomputed.decay_applied == checkpoint.decay_applied
        && recomputed.denials_by_reason_code == checkpoint.denials_by_reason_code
        && recomputed.receipt_chain_head_hash == checkpoint.receipt_chain_head_hash
        && recomputed.standing_policy_hash == checkpoint.standing_policy_hash
        && recomputed.epoch == checkpoint.epoch;
    if !recomputation_matches {
        return Err(InstitutioError::RecomputationMismatch(
            "checkpoint values do not match recomputation from the named chain head".into(),
        ));
    }
    let checkpoint_sig_valid = match &checkpoint.checkpoint_sig {
        None => None,
        Some(entry) => {
            let Some(pinned) = operator_keys.get(&entry.key_id) else {
                return Err(InstitutioError::UntrustedKey(format!(
                    "checkpoint operator key {:?} is not in the pinned trust set",
                    entry.key_id
                )));
            };
            if entry.verifying_key != pinned.to_bytes().to_vec() {
                return Err(InstitutioError::UntrustedKey(format!(
                    "checkpoint carries a verifying key for {:?} that differs from the pinned key",
                    entry.key_id
                )));
            }
            if !verify_ed25519(
                pinned,
                CHECKPOINT_PAYLOAD_TYPE,
                &checkpoint.signing_bytes(),
                &entry.signature,
            ) {
                return Err(InstitutioError::SignatureInvalid(
                    "checkpoint operator signature does not verify under the pinned key"
                        .into(),
                ));
            }
            Some(true)
        }
    };
    let mut valid_cosigs = 0usize;
    let mut counted: Vec<String> = Vec::new();
    for entry in &checkpoint.witness_cosigs {
        let named = policy
            .witness_policy
            .as_ref()
            .map(|w| w.witness_key_ids.contains(&entry.key_id))
            .unwrap_or(false);
        if !named || counted.contains(&entry.key_id) {
            continue;
        }
        let Some(expected_key) = witness_keys.get(&entry.key_id) else {
            continue;
        };
        if *expected_key != entry.verifying_key {
            continue;
        }
        let valid = verifying_key_from_bytes(&entry.verifying_key)
            .map(|key| {
                verify_ed25519(
                    &key,
                    CHECKPOINT_PAYLOAD_TYPE,
                    &checkpoint.signing_bytes(),
                    &entry.signature,
                )
            })
            .unwrap_or(false);
        if valid {
            valid_cosigs += 1;
            counted.push(entry.key_id.clone());
        }
    }
    let quorum_met = policy
        .witness_policy
        .as_ref()
        .map(|w| valid_cosigs >= w.quorum);
    if quorum_met == Some(false) {
        let required = policy
            .witness_policy
            .as_ref()
            .map(|w| w.quorum)
            .unwrap_or(0);
        return Err(InstitutioError::SignatureInvalid(format!(
            "witness quorum not met: {valid_cosigs} valid cosignatures, {required} required"
        )));
    }
    Ok(CheckpointVerdict {
        recomputation_matches,
        checkpoint_sig_valid,
        valid_witness_cosigs: valid_cosigs,
        quorum_met,
        internal_only: checkpoint.witness_cosigs.is_empty(),
    })
}

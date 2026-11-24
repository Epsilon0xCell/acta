//! ComputeStanding: Receipt-Minted Authority, specification
//! Section 16.
//!
//! Author: Gavin Blacklock
//!
//! THE ONE DEFINITION. This function is the only ComputeStanding in
//! the Rust workspace, and it is written from the specification text
//! of Section 16, not from the Python prototype's provisional
//! numbers. The prototype (`code/institutio/standing.py`) carries
//! defaults the specification never fixed (a burn unit of 5, default
//! multipliers of 1, a default ceiling curve, a correlated divisor
//! of 4). None of those defaults exist here. Where the
//! specification fixes the mathematics, this module implements
//! exactly that:
//!
//! - Standing is per scope class, a pure deterministic function of
//!   the receipt chain, the charter `standing_policy`, and the
//!   evaluation time, integer arithmetic only (Section 16.1, I2).
//! - Mint comes only from ACTION receipts: `mint_rate` per unit of
//!   `risk_weight`, from work inside its then-current ceiling, at
//!   full weight only with a counterparty countersignature that
//!   VERIFIES under the counterparty's pinned key over the bound
//!   outcome descriptor (receipt id, arguments hash, result hash,
//!   and risk weight included), where the `countersign_policy`
//!   requires one, clipped by the per-epoch mint cap and the
//!   diversity caps before it counts (I4). Presence of a signature
//!   field is not a countersignature (re-audit finding N4).
//! - Burn is super-linear: the n-th denial in a class burns
//!   `burn_unit * burn_multipliers[code] * n * n`, and a severe
//!   denial also burns a policy fraction across every other class
//!   the agent has touched (I5). The quadratic form is the closed
//!   form Section 16.10, decision 2, fixes (the engineering
//!   blueprint's proposed integer form, rule D4), and the severe
//!   floor is a policy-validation condition there, not a
//!   computation-time adjustment here.
//! - Decay is exponential at the class half-life, applied per mint
//!   event in whole half-lives: an event of age `a` contributes
//!   `amount >> (a / half_life)`. The whole-half-life discretisation
//!   is Section 16.10, decision 4.
//! - A KILL-BURN receipt zeroes the agent in every class from that
//!   point on, including the sub-delegation subtree it names (I7,
//!   Section 16.6), and later actions mint nothing.
//! - Standing is non-transferable and a new agent starts at zero
//!   (I3): an agent with no receipts has no entry, which is zero in
//!   every class.
//!
//! Every encoding this module relies on is decided by
//! Section 16.10: the burn base (decision 1), the epoch
//! (decision 3), the evaluation time as an explicit argument
//! defaulting to the chain's latest timestamp (decision 5), hop
//! attenuation in parts per million scaling both mint and ceilings
//! (decision 6), the correlated burn fraction (decision 7), the
//! diversity caps in absolute and fraction-of-mint-cap forms,
//! including the subtree cap keyed by `subtree_root_id`
//! (decision 8), burns never decaying (decision 12), and Standing
//! as an unbounded non-negative integer under checked arithmetic
//! (decision 14). What still stops this module with
//! [`InstitutioError::UnspecifiedBySpec`] is a policy that omits a
//! value Section 16.10 requires the policy itself to state (a
//! class's `mint_rate`, `burn_unit`, a burn multiplier, a
//! half-life, a hop factor, a correlated fraction, a ceiling
//! curve, or the mint cap a fraction diversity cap divides).
//! Inheritance is reserved and out of v0.1 scope (decision 13):
//! nothing here consumes `inheritance_factor_ppm`, by the amended
//! text, not by omission.

use crate::error::{InstitutioError, Result, UnspecifiedField};
use crate::policy::{CeilingTier, StandingPolicy, PPM};
use acta_core::{DenialReason, ReceiptType, SignedReceipt};
use serde_json::Value;
use std::collections::BTreeMap;

/// The Standing-relevant view of one receipt. Built either from a
/// native signed Acta receipt (the `institutio.*` verdict fields of
/// Section 16.3) or, for conformance, from a Python prototype
/// fixture receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingReceipt {
    /// Receipt type.
    pub receipt_type: ReceiptType,
    /// Integer timestamp, seconds.
    pub timestamp: i64,
    /// Acting agent identity.
    pub agent_id: String,
    /// Action or tool name.
    pub action_name: String,
    /// The Standing scope class the action was computed under.
    pub scope_class: String,
    /// Risk weight, computed by the gate before execution.
    pub risk_weight: u64,
    /// Counterparty identity, when recorded.
    pub counterparty_id: Option<String>,
    /// The counterparty countersignature bytes, when recorded.
    /// Verified cryptographically at computation time against the
    /// pinned counterparty keys (finding N4); never trusted for
    /// its presence alone.
    pub counterparty_sig: Option<Vec<u8>>,
    /// Receipt identity bound into the countersigned descriptor.
    pub receipt_id: Option<String>,
    /// Arguments hash bound into the countersigned descriptor.
    pub arguments_hash: Option<String>,
    /// Result hash bound into the countersigned descriptor.
    pub result_hash: Option<String>,
    /// Delegation depth of the acting seat for this action.
    pub delegation_depth: u32,
    /// Denial reason code, on DENIAL receipts.
    pub reason_code: Option<DenialReason>,
    /// Burn amount recorded on a BURN receipt, when present.
    pub burn_amount: Option<u64>,
    /// Agent identities in the killed subtree, on KILL-BURN
    /// receipts, beyond the receipt's own agent.
    pub kill_targets: Vec<String>,
    /// The child seat rooting the subtree this action belongs to
    /// (Section 16.3, receipt extension 6), for the subtree
    /// diversity cap of Section 16.10, decision 8. Absent means the
    /// acting agent's own subtree.
    pub subtree_root_id: Option<String>,
}

fn verdict_text(verdict: &acta_core::cbor::CborValue, key: &str) -> Option<String> {
    match verdict {
        acta_core::cbor::CborValue::Map(map) => match map.get(key) {
            Some(acta_core::cbor::CborValue::Text(t)) => Some(t.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn verdict_int(verdict: &acta_core::cbor::CborValue, key: &str) -> Option<i64> {
    match verdict {
        acta_core::cbor::CborValue::Map(map) => match map.get(key) {
            Some(acta_core::cbor::CborValue::Int(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

fn verdict_bytes(verdict: &acta_core::cbor::CborValue, key: &str) -> Option<Vec<u8>> {
    match verdict {
        acta_core::cbor::CborValue::Map(map) => match map.get(key) {
            Some(acta_core::cbor::CborValue::Bytes(b)) => Some(b.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn verdict_text_list(verdict: &acta_core::cbor::CborValue, key: &str) -> Vec<String> {
    match verdict {
        acta_core::cbor::CborValue::Map(map) => match map.get(key) {
            Some(acta_core::cbor::CborValue::Array(items)) => items
                .iter()
                .filter_map(|i| match i {
                    acta_core::cbor::CborValue::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

impl StandingReceipt {
    /// Build the Standing view of a native signed receipt. The
    /// Section 16.3 extension fields are read from the receipt's
    /// verdict map; a receipt without them computes under the class
    /// `default`, with risk weight 0 (it mints nothing until the
    /// gate records a weight: no recorded weight, no mint).
    ///
    /// Repair round 3, finding S2: a negative verdict integer
    /// (delegation depth, risk weight, burn amount) is a parse
    /// error, never clamped to zero. Clamping a negative depth to
    /// zero silently granted full, unattenuated mint; the Python
    /// prototype rejects the same input, and the two trees are one
    /// definition.
    pub fn from_signed(signed: &SignedReceipt) -> Result<Self> {
        let body = &signed.body;
        let none = acta_core::cbor::CborValue::Null;
        let verdict = body.verdict.as_ref().unwrap_or(&none);
        let non_negative = |key: &str| -> Result<Option<u64>> {
            match verdict_int(verdict, key) {
                None => Ok(None),
                Some(n) if n < 0 => Err(InstitutioError::Acta(format!(
                    "verdict field {key} is negative ({n}); a negative \
                     verdict integer is a parse error, never clamped \
                     (finding S2)"
                ))),
                Some(n) => Ok(Some(n as u64)),
            }
        };
        Ok(StandingReceipt {
            receipt_type: body.receipt_type,
            timestamp: body.timestamp,
            agent_id: body.agent.id.clone(),
            action_name: body.action.name.clone(),
            scope_class: verdict_text(verdict, "standing_scope_class")
                .unwrap_or_else(|| "default".to_string()),
            risk_weight: non_negative("risk_weight")?.unwrap_or(0),
            counterparty_id: verdict_text(verdict, "counterparty_id"),
            counterparty_sig: verdict_bytes(verdict, "counterparty_sig"),
            receipt_id: Some(body.receipt_id.clone()),
            arguments_hash: Some(body.action.arguments_hash.clone()),
            result_hash: Some(body.result_hash.clone()),
            delegation_depth: non_negative("delegation_depth")?
                .map(|n| n as u32)
                .unwrap_or(0),
            reason_code: body.reason_code,
            burn_amount: non_negative("burn_amount")?,
            kill_targets: verdict_text_list(verdict, "killed_agent_ids"),
            subtree_root_id: verdict_text(verdict, "subtree_root_id"),
        })
    }

    /// Build the Standing view of a Python prototype fixture receipt
    /// (plain JSON, unsigned segment entries). Used only by the
    /// conformance runner, so the prototype's Standing fixtures run
    /// against this one definition.
    pub fn from_prototype_json(value: &Value) -> Result<Self> {
        let action = value.get("action").cloned().unwrap_or(Value::Null);
        // Section 16.10, decision 24, rows (a) to (c) (repair
        // round 5): a stated receipt scalar is read strictly. The
        // field picker this replaces skipped nulls, so a stated
        // null risk_weight read as absent and defaulted (fourth
        // re-audit finding S2 residue), a non-string receipt_id
        // was silently erased (finding T2 residue), and a float
        // or string timestamp mapped to 0 (finding U5). A stated
        // null is malformed here, never absence.
        let pick = |keys: &[&str]| -> Result<Option<Value>> {
            for key in keys {
                for source in [value, &action] {
                    if let Some(v) = source.get(key) {
                        if v.is_null() {
                            return Err(InstitutioError::Acta(format!(
                                "prototype receipt field {key} is stated \
                                 as null; a stated null is a malformed \
                                 value, never an absent field \
                                 (Section 16.10 decision 24)"
                            )));
                        }
                        return Ok(Some(v.clone()));
                    }
                }
            }
            Ok(None)
        };
        let pick_text = |keys: &[&str], field: &str| -> Result<Option<String>> {
            match pick(keys)? {
                None => Ok(None),
                Some(v) => Ok(Some(v.as_str().ok_or_else(|| {
                    InstitutioError::Acta(format!(
                        "prototype receipt {field} is not a string"
                    ))
                })?.to_string())),
            }
        };
        let receipt_type = ReceiptType::from_wire(
            value
                .get("receipt_type")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        // A present but non-integer risk weight or delegation
        // depth is malformed input, not a default (re-audit minor
        // r3, prototype-JSON path; the native path is CBOR-typed
        // and cannot represent either).
        let risk_weight = match pick(&["risk_weight"])? {
            None => 1,
            Some(v) => v.as_u64().ok_or_else(|| {
                InstitutioError::Acta(
                    "prototype receipt risk_weight is not a non-negative integer".into(),
                )
            })?,
        };
        let delegation_depth = match pick(&["delegation_depth"])? {
            None => 0,
            Some(v) => v.as_u64().ok_or_else(|| {
                InstitutioError::Acta(
                    "prototype receipt delegation_depth is not a non-negative integer"
                        .into(),
                )
            })? as u32,
        };
        // A timestamp is an integer number of seconds or the
        // receipt is malformed (finding U5): a float, string,
        // boolean, stated null, or negative timestamp is an
        // error, never mapped to 0. Absence remains 0.
        let timestamp = match value.get("timestamp") {
            None => 0,
            Some(v) => v.as_i64().filter(|t| *t >= 0).ok_or_else(|| {
                InstitutioError::Acta(
                    "prototype receipt timestamp is not a non-negative \
                     integer number of seconds"
                        .into(),
                )
            })?,
        };
        // A non-string receipt_id is malformed, never silently
        // erased (finding T2 residue): an identity the parser
        // cannot see cannot be checked for uniqueness under
        // decision 19. The Python computation rejects the same
        // input.
        let receipt_id = match value.get("receipt_id") {
            None => None,
            Some(v) => Some(v.as_str().ok_or_else(|| {
                InstitutioError::Acta(
                    "prototype receipt receipt_id is not a string".into(),
                )
            })?.to_string()),
        };
        // The scope class: a stated non-string or null in either
        // location is malformed; an empty string falls through
        // to the next location, as the Python reader falls
        // through.
        let scope_class = {
            let mut found = None;
            for text in [
                pick_text(&["standing_scope_class"], "standing_scope_class")?,
                pick_text(&["scope_class"], "scope_class")?,
            ]
            .into_iter()
            .flatten()
            {
                if !text.is_empty() {
                    found = Some(text);
                    break;
                }
            }
            found.unwrap_or_else(|| "default".to_string())
        };
        Ok(StandingReceipt {
            receipt_type,
            timestamp,
            // The agent field is the specification's agent
            // object: a stated agent in any other shape (a bare
            // string, a stated null) is a parse error, never a
            // silently absent id and an empty computation
            // (fifth re-audit finding W5; the Python computation
            // raises a validation error on the same input).
            // Absence remains an empty id, as before.
            agent_id: match value.get("agent") {
                None => String::new(),
                Some(agent) => agent
                    .as_object()
                    .ok_or_else(|| {
                        InstitutioError::Acta(
                            "prototype receipt agent is not an object".into(),
                        )
                    })?
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            },
            action_name: action
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            scope_class,
            risk_weight,
            counterparty_id: pick_text(&["counterparty_id"], "counterparty_id")?,
            counterparty_sig: pick(&["counterparty_sig"])?.map(|v| match v {
                // A 128-character hex string is the fixture
                // transport form of a 64-byte Ed25519 signature
                // (the differential test carries real signatures
                // this way); anything else keeps the raw-bytes
                // form the prototype fixtures use.
                Value::String(s) if s.len() == 128
                    && s.bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    (0..64)
                        .map(|i| {
                            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                                .expect("hex checked above")
                        })
                        .collect()
                }
                Value::String(s) => s.into_bytes(),
                other => other.to_string().into_bytes(),
            }),
            receipt_id,
            arguments_hash: action
                .get("arguments_hash")
                .and_then(Value::as_str)
                .map(str::to_string),
            result_hash: value
                .get("result_hash")
                .and_then(Value::as_str)
                .map(str::to_string),
            delegation_depth,
            reason_code: value
                .get("reason_code")
                .and_then(Value::as_str)
                .and_then(DenialReason::from_wire),
            // A present burn_amount that is negative or not an
            // integer is malformed, never silently dropped to
            // none (third re-audit minor t5, repair round 4): the
            // Python computation raises on the same input.
            burn_amount: match pick(&["burn_amount"])? {
                None => None,
                Some(v) => Some(v.as_u64().ok_or_else(|| {
                    InstitutioError::Acta(
                        "prototype receipt burn_amount is not a non-negative integer"
                            .into(),
                    )
                })?),
            },
            // Section 16.10 decision 17 (finding S4): the kill
            // subtree travels under the single field name
            // killed_agent_ids, in the prototype path as in every
            // other path. This constructor once hardcoded an empty
            // list, so a prototype KILL-BURN named nobody here.
            kill_targets: value
                .get("killed_agent_ids")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            subtree_root_id: pick_text(&["subtree_root_id"], "subtree_root_id")?,
        })
    }
}

/// The DSSE payload type of a counterparty outcome countersignature.
/// Identical to the Python prototype's COUNTERPARTY_PAYLOAD_TYPE, so
/// a descriptor means the same bytes in both implementations.
pub const COUNTERPARTY_PAYLOAD_TYPE: &str =
    "application/vnd.acta.counterparty-outcome.v0.1+json";

/// The exact bytes a counterparty countersignature covers: the
/// bound outcome descriptor of Section 16.4, invariant I4. It names
/// the agent, the action, the scope class, the timestamp, the risk
/// weight the gate computed from the signed manifest, and the
/// receipt's own identity (receipt id, arguments hash, result
/// hash), so a signature made for one receipt cannot be replayed
/// onto another receipt or re-weighted (re-audit finding M2,
/// mirrored here under finding N4). The field set is fixed by
/// Section 16.10 decision 16 (repair round 3, finding S1): exactly
/// agent_id, action_name, arguments_hash, receipt_id, result_hash,
/// risk_weight, scope_class, timestamp. Serialised with acta-core's
/// canonical JSON, byte-identical to the Python prototype's
/// `counterparty_outcome_bytes`. Fields a receipt does not carry
/// are signed as null.
#[allow(clippy::too_many_arguments)]
pub fn counterparty_outcome_bytes(
    agent_id: &str,
    action_name: &str,
    scope_class: &str,
    timestamp: i64,
    risk_weight: u64,
    receipt_id: Option<&str>,
    arguments_hash: Option<&str>,
    result_hash: Option<&str>,
) -> Vec<u8> {
    let descriptor = serde_json::json!({
        "agent_id": agent_id,
        "action_name": action_name,
        "arguments_hash": arguments_hash,
        "receipt_id": receipt_id,
        "result_hash": result_hash,
        "risk_weight": risk_weight,
        "scope_class": scope_class,
        "timestamp": timestamp,
    });
    acta_core::legacy::canonical_json_bytes(&descriptor)
        .expect("descriptor contains only canonical-encodable values")
}

/// Produce a counterparty countersignature over the bound outcome
/// descriptor, with the counterparty's own signer.
#[allow(clippy::too_many_arguments)]
pub fn countersign_outcome(
    signer: &acta_core::Ed25519Signer,
    agent_id: &str,
    action_name: &str,
    scope_class: &str,
    timestamp: i64,
    risk_weight: u64,
    receipt_id: Option<&str>,
    arguments_hash: Option<&str>,
    result_hash: Option<&str>,
) -> Vec<u8> {
    use acta_core::Signer;
    signer.sign_pae(
        COUNTERPARTY_PAYLOAD_TYPE,
        &counterparty_outcome_bytes(
            agent_id,
            action_name,
            scope_class,
            timestamp,
            risk_weight,
            receipt_id,
            arguments_hash,
            result_hash,
        ),
    )
}

/// True only when the receipt carries a countersignature that
/// verifies under the pinned key for its named counterparty, over
/// the bound descriptor built from the receipt's own fields.
fn countersignature_verifies(
    receipt: &StandingReceipt,
    counterparty_keys: &BTreeMap<String, Vec<u8>>,
) -> bool {
    let (Some(counterparty_id), Some(signature)) =
        (&receipt.counterparty_id, &receipt.counterparty_sig)
    else {
        return false;
    };
    let Some(key_bytes) = counterparty_keys.get(counterparty_id) else {
        return false;
    };
    let Ok(key) = acta_core::signing::verifying_key_from_bytes(key_bytes) else {
        return false;
    };
    let descriptor = counterparty_outcome_bytes(
        &receipt.agent_id,
        &receipt.action_name,
        &receipt.scope_class,
        receipt.timestamp,
        receipt.risk_weight,
        receipt.receipt_id.as_deref(),
        receipt.arguments_hash.as_deref(),
        receipt.result_hash.as_deref(),
    );
    acta_core::signing::verify_ed25519(&key, COUNTERPARTY_PAYLOAD_TYPE, &descriptor, signature)
}

/// The authority ceilings a Standing value implies, in the six
/// dimensions of the ceiling curve (Section 16.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceilings {
    /// Maximum budget per action.
    pub max_budget_per_action: u64,
    /// Maximum budget per epoch.
    pub max_budget_per_epoch: u64,
    /// Maximum irreversibility class, 0 to 3.
    pub max_irreversibility: u64,
    /// Maximum data sensitivity.
    pub max_data_sensitivity: u64,
    /// Maximum delegation depth.
    pub max_delegation_depth: u64,
    /// Maximum fanout, children per epoch.
    pub max_fanout: u64,
}

impl From<&CeilingTier> for Ceilings {
    fn from(tier: &CeilingTier) -> Self {
        Ceilings {
            max_budget_per_action: tier.max_budget_per_action,
            max_budget_per_epoch: tier.max_budget_per_epoch,
            max_irreversibility: tier.max_irreversibility,
            max_data_sensitivity: tier.max_data_sensitivity,
            max_delegation_depth: tier.max_delegation_depth,
            max_fanout: tier.max_fanout,
        }
    }
}

/// Effective authority, Section 16.1: the field-by-field minimum of
/// the charter grant, the delegation manifest, and the Standing
/// ceiling. The result never exceeds any of its three inputs.
pub fn effective_authority(grant: &Ceilings, manifest: &Ceilings, standing: &Ceilings) -> Ceilings {
    Ceilings {
        max_budget_per_action: grant
            .max_budget_per_action
            .min(manifest.max_budget_per_action)
            .min(standing.max_budget_per_action),
        max_budget_per_epoch: grant
            .max_budget_per_epoch
            .min(manifest.max_budget_per_epoch)
            .min(standing.max_budget_per_epoch),
        max_irreversibility: grant
            .max_irreversibility
            .min(manifest.max_irreversibility)
            .min(standing.max_irreversibility),
        max_data_sensitivity: grant
            .max_data_sensitivity
            .min(manifest.max_data_sensitivity)
            .min(standing.max_data_sensitivity),
        max_delegation_depth: grant
            .max_delegation_depth
            .min(manifest.max_delegation_depth)
            .min(standing.max_delegation_depth),
        max_fanout: grant
            .max_fanout
            .min(manifest.max_fanout)
            .min(standing.max_fanout),
    }
}

/// The ceilings a Standing value reaches in one scope class: the
/// highest curve tier whose `min_standing` the value reaches, with
/// the budget dimensions attenuated by the class hop factor raised
/// to the delegation depth (invariant I7).
pub fn ceilings_for_standing(
    policy: &StandingPolicy,
    scope_class: &str,
    standing: u64,
    delegation_depth: u32,
) -> Result<Ceilings> {
    // Section 16.10, decision 21: a class curve overrides the
    // policy-level curve for that class, identically in both
    // implementations.
    let curve = policy
        .scope_classes
        .get(scope_class)
        .and_then(|c| c.ceiling_curve.as_ref())
        .or(policy.ceiling_curve.as_ref())
        .ok_or(InstitutioError::UnspecifiedBySpec(
            UnspecifiedField::CeilingCurve,
        ))?;
    let mut tiers: Vec<&CeilingTier> = curve.iter().collect();
    tiers.sort_by_key(|t| t.min_standing);
    let mut chosen = tiers.first().copied().ok_or(InstitutioError::PolicyInvalid(
        "ceiling_curve is empty".into(),
    ))?;
    for tier in tiers {
        if standing >= tier.min_standing {
            chosen = tier;
        }
    }
    let mut ceilings = Ceilings::from(chosen);
    if delegation_depth > 0 {
        let class = policy.scope_classes.get(scope_class);
        let ppm = class
            .and_then(|c| c.hop_attenuation_ppm)
            .ok_or(InstitutioError::UnspecifiedBySpec(
                UnspecifiedField::HopAttenuation,
            ))?;
        ceilings.max_budget_per_action =
            attenuate(ceilings.max_budget_per_action, ppm, delegation_depth)?;
        ceilings.max_budget_per_epoch =
            attenuate(ceilings.max_budget_per_epoch, ppm, delegation_depth)?;
    }
    Ok(ceilings)
}

/// `amount * ppm^depth / PPM^depth`, truncating down, checked.
fn attenuate(amount: u64, ppm: u64, depth: u32) -> Result<u64> {
    let numerator = (ppm as i128)
        .checked_pow(depth)
        .ok_or(InstitutioError::Overflow)?;
    let denominator = (PPM as i128)
        .checked_pow(depth)
        .ok_or(InstitutioError::Overflow)?;
    let scaled = (amount as i128)
        .checked_mul(numerator)
        .ok_or(InstitutioError::Overflow)?;
    Ok((scaled / denominator) as u64)
}

/// The computed Standing of one scope class, with the tallies a
/// checkpoint carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassStanding {
    /// Final Standing: decayed mint minus burn, floored at zero,
    /// and zero in every class after a kill.
    pub standing: u64,
    /// Ceilings the final Standing implies, when the policy carries
    /// a ceiling curve.
    pub ceilings: Option<Ceilings>,
    /// Total minted before decay.
    pub minted: u64,
    /// Mint remaining after decay, before burn.
    pub minted_decayed: u64,
    /// Decay applied: minted minus minted_decayed.
    pub decay_applied: u64,
    /// Total burned by denials, including correlated burn.
    pub burned: u64,
    /// Burn amounts recorded on BURN receipts (tallied, never
    /// double-counted: the DENIAL already burned).
    pub burn_recorded: u64,
    /// ACTION receipts seen for the agent in this class.
    pub actions: u64,
    /// DENIAL receipts seen for the agent in this class.
    pub denials: u64,
    /// PROMOTION receipts seen (tallied; they confer nothing).
    pub promotions: u64,
    /// DEMOTION receipts seen (tallied; they confer nothing).
    pub demotions: u64,
    /// True when a KILL-BURN has zeroed this agent.
    pub killed: bool,
}

#[derive(Default)]
struct ClassState {
    mint_events: Vec<(i64, i128)>,
    minted_pre_decay: i128,
    burned: i128,
    burn_recorded: i128,
    actions: u64,
    denials: u64,
    promotions: u64,
    demotions: u64,
    last_depth: u32,
    epoch_mint: BTreeMap<i64, i128>,
    epoch_counterparty: BTreeMap<(i64, String), i128>,
    epoch_task: BTreeMap<(i64, String), i128>,
    epoch_subtree: BTreeMap<(i64, String), i128>,
}

/// The binding diversity cap for one dimension, under
/// Section 16.10, decision 8: the absolute per-epoch form and the
/// fraction form (a fraction of the class `mint_cap_per_epoch`)
/// are both conforming, and where both are stated the smaller
/// binds. A fraction form without a mint cap to divide is an
/// unspecified-by-policy error, because the denominator is missing.
fn diversity_cap(
    absolute: Option<u64>,
    fraction_ppm: Option<u64>,
    mint_cap_per_epoch: Option<u64>,
    class_name: &str,
) -> Result<Option<u64>> {
    let fraction_cap = match fraction_ppm {
        None => None,
        Some(ppm) => {
            let cap = mint_cap_per_epoch.ok_or_else(|| {
                InstitutioError::UnspecifiedBySpec(UnspecifiedField::MintCapPerEpoch(
                    class_name.to_string(),
                ))
            })?;
            let scaled = (cap as u128)
                .checked_mul(ppm as u128)
                .ok_or(InstitutioError::Overflow)?
                / PPM as u128;
            Some(scaled as u64)
        }
    };
    Ok(match (absolute, fraction_cap) {
        (Some(a), Some(f)) => Some(a.min(f)),
        (Some(a), None) => Some(a),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    })
}

fn clip(amount: i128, used: i128, cap: Option<u64>) -> i128 {
    match cap {
        None => amount,
        Some(cap) => {
            let remaining = cap as i128 - used;
            if remaining <= 0 {
                0
            } else {
                amount.min(remaining)
            }
        }
    }
}

fn clamp_u64(value: i128) -> u64 {
    if value <= 0 {
        0
    } else if value > u64::MAX as i128 {
        u64::MAX
    } else {
        value as u64
    }
}

/// ComputeStanding: the one definition. See the module
/// documentation for the rules and the policy omissions it stops
/// on.
///
/// `receipts` is the full chain segment in chain order; the
/// computation selects the receipts of `agent_id`, while KILL-BURN
/// receipts are honoured chain-wide because a parent's kill burns
/// its subtree (I7). `eval_time` defaults to the latest timestamp in
/// the segment. An agent with no receipts returns an empty map:
/// zero in every class (I3).
///
/// `counterparty_keys` is the verification material for
/// countersignatures: counterparty id to its pinned 32-byte
/// Ed25519 verifying key, supplied from the trust input or the
/// charter key set, never from the receipts themselves (finding
/// N4). Where the policy requires a countersignature for a class,
/// an action whose countersignature is absent, names an unknown
/// counterparty, or fails verification mints zero.
pub fn compute_standing(
    receipts: &[StandingReceipt],
    policy: &StandingPolicy,
    agent_id: &str,
    eval_time: Option<i64>,
    counterparty_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, ClassStanding>> {
    // Section 16.10, decision 15 and decision 24, row (e)
    // (repair round 5, fourth re-audit finding S5 residue): the
    // witness policy's quorum bounds are checked at computation
    // entry, not only in validate_policy and at checkpoint
    // verification, so a caller who only computes gets the same
    // policy in both trees.
    if let Some(witness) = &policy.witness_policy {
        if witness.quorum == 0 || witness.quorum > witness.witness_key_ids.len() {
            return Err(InstitutioError::PolicyInvalid(format!(
                "witness_policy quorum {} is outside 1..={} \
                 (Section 16.10 decision 15)",
                witness.quorum,
                witness.witness_key_ids.len()
            )));
        }
    }
    // Section 16.10, decision 3: an epoch length, where stated, is
    // at least one second. Zero is a policy error, never a synonym
    // for absent (repair round 3, minor s5).
    if policy.epoch_seconds == Some(0) {
        return Err(InstitutioError::PolicyInvalid(
            "epoch_seconds must be at least 1 when present".into(),
        ));
    }
    // Section 16.10, decision 19: receipt identities are unique
    // within a chain, and a segment carrying two receipts with one
    // receipt_id is invalid. The Python computation refuses the
    // same segment; this tree once minted on both receipts (third
    // re-audit finding T2, repair round 4).
    {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for receipt in receipts {
            if let Some(id) = receipt.receipt_id.as_deref() {
                if !seen.insert(id) {
                    return Err(InstitutioError::Acta(format!(
                        "DUPLICATE_RECEIPT_ID: receipt_id {id} appears \
                         more than once in the segment; receipt \
                         identities are unique (Section 16.10 \
                         decision 19)"
                    )));
                }
            }
        }
    }
    let eval = eval_time.unwrap_or_else(|| {
        receipts.iter().map(|r| r.timestamp).max().unwrap_or(0)
    });
    let mut states: BTreeMap<String, ClassState> = BTreeMap::new();
    // Section 16.10, decision 7 (re-audit minor r9): the classes a
    // severe denial's correlated burn reaches are every other class
    // in which the agent has at least one receipt in the segment,
    // including classes first touched after the denial. Pre-create
    // their states so the burn lands there.
    for receipt in receipts {
        if receipt.agent_id == agent_id {
            states.entry(receipt.scope_class.clone()).or_default();
        }
    }
    let mut agent_killed = false;
    for receipt in receipts {
        if receipt.receipt_type == ReceiptType::KillBurn
            && (receipt.agent_id == agent_id || receipt.kill_targets.iter().any(|t| t == agent_id))
        {
            agent_killed = true;
            for state in states.values_mut() {
                state.mint_events.clear();
            }
            continue;
        }
        if receipt.agent_id != agent_id {
            continue;
        }
        let class_name = receipt.scope_class.clone();
        let class = policy.scope_classes.get(&class_name);
        {
            let state = states.entry(class_name.clone()).or_default();
            state.last_depth = receipt.delegation_depth;
        }
        match receipt.receipt_type {
            ReceiptType::Action => {
                let state = states.get_mut(&class_name).expect("inserted above");
                state.actions += 1;
                if agent_killed {
                    continue;
                }
                let mint_rate = class
                    .and_then(|c| c.mint_rate)
                    .ok_or_else(|| {
                        InstitutioError::UnspecifiedBySpec(UnspecifiedField::MintRate(
                            class_name.clone(),
                        ))
                    })?;
                let mut amount = (mint_rate as i128)
                    .checked_mul(receipt.risk_weight as i128)
                    .ok_or(InstitutioError::Overflow)?;
                if receipt.delegation_depth > 0 {
                    let ppm = class
                        .and_then(|c| c.hop_attenuation_ppm)
                        .ok_or(InstitutioError::UnspecifiedBySpec(
                            UnspecifiedField::HopAttenuation,
                        ))?;
                    amount = attenuate(amount.max(0) as u64, ppm, receipt.delegation_depth)?
                        as i128;
                }
                if policy.countersign_required.contains(&class_name)
                    && !countersignature_verifies(receipt, counterparty_keys)
                {
                    amount = 0;
                }
                let epoch = policy.epoch_of(receipt.timestamp);
                amount = clip(amount, *state.epoch_mint.get(&epoch).unwrap_or(&0), class.and_then(|c| c.mint_cap_per_epoch));
                let mint_cap = class.and_then(|c| c.mint_cap_per_epoch);
                let cp_cap = diversity_cap(
                    policy.diversity_cap_per_counterparty,
                    policy.diversity_fraction_per_counterparty_ppm,
                    mint_cap,
                    &class_name,
                )?;
                let task_cap = diversity_cap(
                    policy.diversity_cap_per_task_type,
                    policy.diversity_fraction_per_task_type_ppm,
                    mint_cap,
                    &class_name,
                )?;
                let subtree_cap = diversity_cap(
                    None,
                    policy.diversity_fraction_per_subtree_ppm,
                    mint_cap,
                    &class_name,
                )?;
                let counterparty = receipt
                    .counterparty_id
                    .clone()
                    .unwrap_or_else(|| "none".to_string());
                let cp_key = (epoch, counterparty);
                amount = clip(
                    amount,
                    *state.epoch_counterparty.get(&cp_key).unwrap_or(&0),
                    cp_cap,
                );
                let task_key = (epoch, receipt.action_name.clone());
                amount = clip(
                    amount,
                    *state.epoch_task.get(&task_key).unwrap_or(&0),
                    task_cap,
                );
                // The subtree dimension (Section 16.10, decision 8),
                // keyed by the receipt's subtree root, or by the
                // acting agent for its own subtree.
                let subtree_key = (
                    epoch,
                    receipt
                        .subtree_root_id
                        .clone()
                        .unwrap_or_else(|| receipt.agent_id.clone()),
                );
                amount = clip(
                    amount,
                    *state.epoch_subtree.get(&subtree_key).unwrap_or(&0),
                    subtree_cap,
                );
                if amount > 0 {
                    *state.epoch_mint.entry(epoch).or_insert(0) += amount;
                    *state.epoch_counterparty.entry(cp_key).or_insert(0) += amount;
                    *state.epoch_task.entry(task_key).or_insert(0) += amount;
                    *state.epoch_subtree.entry(subtree_key).or_insert(0) += amount;
                    state.mint_events.push((receipt.timestamp, amount));
                    state.minted_pre_decay += amount;
                }
            }
            ReceiptType::Denial => {
                let code = receipt
                    .reason_code
                    .ok_or_else(|| {
                        InstitutioError::Acta(
                            "DENIAL receipt without a reason code reached ComputeStanding"
                                .into(),
                        )
                    })?;
                let burn_unit = class.and_then(|c| c.burn_unit).ok_or(
                    InstitutioError::UnspecifiedBySpec(UnspecifiedField::BurnUnit),
                )?;
                let multiplier = class
                    .and_then(|c| c.burn_multipliers.get(code.as_str()))
                    .copied()
                    .ok_or_else(|| {
                        InstitutioError::UnspecifiedBySpec(UnspecifiedField::BurnMultiplier(
                            code.as_str().to_string(),
                        ))
                    })?;
                let ordinal = {
                    let state = states.get_mut(&class_name).expect("inserted above");
                    state.denials += 1;
                    state.denials as i128
                };
                let burn = (burn_unit as i128)
                    .checked_mul(multiplier as i128)
                    .and_then(|b| b.checked_mul(ordinal))
                    .and_then(|b| b.checked_mul(ordinal))
                    .ok_or(InstitutioError::Overflow)?;
                let severe = class
                    .map(|c| c.severe_reason_codes.contains(code.as_str()))
                    .unwrap_or(false);
                // Section 16.10, decision 7: the correlated burn
                // reaches other classes, so the fraction is a
                // required policy statement only when another class
                // exists for this agent in the segment. A
                // single-class segment states no fraction and owes
                // none (repair round 3: this tree once demanded the
                // field where the prototype computed on, so one
                // policy was valid in one tree and an error in the
                // other).
                let others_exist = states.keys().any(|n| n != &class_name);
                if severe && others_exist {
                    let ppm = class
                        .and_then(|c| c.correlated_burn_fraction_ppm)
                        .ok_or(InstitutioError::UnspecifiedBySpec(
                            UnspecifiedField::CorrelatedBurnFraction,
                        ))?;
                    let correlated = burn
                        .checked_mul(ppm as i128)
                        .ok_or(InstitutioError::Overflow)?
                        / PPM as i128;
                    if correlated > 0 {
                        let names: Vec<String> = states.keys().cloned().collect();
                        for name in names {
                            if name != class_name {
                                if let Some(other) = states.get_mut(&name) {
                                    other.burned += correlated;
                                }
                            }
                        }
                    }
                }
                let state = states.get_mut(&class_name).expect("inserted above");
                state.burned += burn;
            }
            ReceiptType::Burn => {
                let state = states.get_mut(&class_name).expect("inserted above");
                state.burn_recorded += receipt.burn_amount.unwrap_or(0) as i128;
            }
            ReceiptType::Promotion => {
                let state = states.get_mut(&class_name).expect("inserted above");
                state.promotions += 1;
            }
            ReceiptType::Demotion => {
                let state = states.get_mut(&class_name).expect("inserted above");
                state.demotions += 1;
            }
            ReceiptType::Grant | ReceiptType::Revocation | ReceiptType::KillBurn => {}
        }
    }
    let mut result = BTreeMap::new();
    for (class_name, state) in &states {
        let class = policy.scope_classes.get(class_name);
        let mut minted_decayed: i128 = 0;
        if !state.mint_events.is_empty() {
            let half_life = class
                .and_then(|c| c.half_life_seconds)
                .ok_or_else(|| {
                    InstitutioError::UnspecifiedBySpec(UnspecifiedField::HalfLife(
                        class_name.clone(),
                    ))
                })?;
            if half_life == 0 {
                // Re-audit finding N3: a zero half-life is a
                // policy error, never a divide by zero.
                return Err(InstitutioError::PolicyInvalid(format!(
                    "scope class {class_name}: half_life_seconds must be at least one second"
                )));
            }
            for (timestamp, amount) in &state.mint_events {
                let age = (eval - *timestamp).max(0);
                let shifts = (age / half_life as i64).min(127);
                minted_decayed += amount >> shifts;
            }
        }
        let standing = if agent_killed {
            0
        } else {
            clamp_u64(minted_decayed - state.burned)
        };
        let minted_decayed = if agent_killed { 0 } else { minted_decayed };
        // Section 16.10, decision 23 (repair round 4): producing
        // ceilings is part of this computation's result (Section
        // 16.1), so a class with neither its own curve nor a
        // policy curve is an unspecified-by-policy error, exactly
        // as the Python computation raises. This tree once
        // returned a Standing with no ceilings where the Python
        // tree errored (third re-audit minor t4).
        let curve_stated = class
            .and_then(|c| c.ceiling_curve.as_ref())
            .is_some()
            || policy.ceiling_curve.is_some();
        if !curve_stated {
            return Err(InstitutioError::UnspecifiedBySpec(
                UnspecifiedField::CeilingCurve,
            ));
        }
        let ceilings = Some(ceilings_for_standing(
            policy,
            class_name,
            standing,
            state.last_depth,
        )?);
        result.insert(
            class_name.clone(),
            ClassStanding {
                standing,
                ceilings,
                minted: clamp_u64(state.minted_pre_decay),
                minted_decayed: clamp_u64(minted_decayed),
                decay_applied: clamp_u64(state.minted_pre_decay - minted_decayed),
                burned: clamp_u64(state.burned),
                burn_recorded: clamp_u64(state.burn_recorded),
                actions: state.actions,
                denials: state.denials,
                promotions: state.promotions,
                demotions: state.demotions,
                killed: agent_killed,
            },
        );
    }
    Ok(result)
}

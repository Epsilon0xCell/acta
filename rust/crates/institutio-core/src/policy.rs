//! The charter `standing_policy` object: parsing and validation.
//!
//! Author: Gavin Blacklock
//!
//! Specification Section 16.3 names the policy's contents, and
//! Section 16.10 (the encoding amendment of 2026-11-23) fixes every
//! encoding and unit: per scope class a `mint_rate`, a
//! `mint_cap_per_epoch`, a `half_life_seconds`, a
//! `hop_attenuation_ppm`, `burn_multipliers` by denial reason code,
//! and a `burn_unit`; a `ceiling_curve` of tiers; a
//! `countersign_policy`; `diversity_caps`; and a `witness_policy`.
//! This module's rule, stated once and applied everywhere: a value
//! Section 16.10 assigns to the policy is read from the policy and
//! never hardcoded; a value the policy omits is carried as `None`
//! here and raised as [`InstitutioError::UnspecifiedBySpec`] at the
//! exact point the computation needs it.
//!
//! The policy fields Section 16.10 names, with their decisions:
//!
//! - `burn_unit`: the base the burn multipliers multiply
//!   (decision 1).
//! - `hop_attenuation_ppm`: the hop factor in parts per million
//!   (decision 6). A bare `hop_attenuation` is accepted only as the
//!   integer 1, read as 1,000,000 ppm.
//! - `correlated_burn_fraction_ppm`: the fraction of a severe burn
//!   applied across correlated classes (invariant I5), in parts per
//!   million (decision 7).
//! - `half_life_seconds`: the half-life in seconds (decision 4). A
//!   bare `half_life` field is accepted as the deprecated alias and
//!   read as seconds.
//! - `epoch_seconds`: the epoch length the per-epoch caps and the
//!   checkpoint epoch count in (decision 3). Absent means a single
//!   epoch.
//! - `diversity_caps`: absolute per-epoch forms
//!   (`per_counterparty_per_epoch`, `per_task_type_per_epoch`) and
//!   fraction forms (`per_counterparty_fraction_ppm`,
//!   `per_task_type_fraction_ppm`, `per_subtree_fraction_ppm`,
//!   fractions of the class `mint_cap_per_epoch`), decision 8.
//! - `severe_reason_codes`: defaults to the codes invariant I5
//!   names in prose (denial for exceeding scope, and for use of a
//!   revoked manifest, which covers replay): `scope` and `revoked`.
//! - `inheritance_factor_ppm`: reserved by decision 13, parsed and
//!   carried, consumed by no v0.1 computation.

use crate::error::{InstitutioError, Result, UnspecifiedField};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Parts per million denominator for all fractional policy fields.
pub const PPM: u64 = 1_000_000;

/// One tier of the ceiling curve: the ceilings a Standing value at
/// or above `min_standing` reaches (Section 16.3, item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingTier {
    /// Minimum Standing for this tier.
    pub min_standing: u64,
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

/// The witness policy of a charter (invariant I8): which witnesses
/// may cosign checkpoints, and the quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessPolicy {
    /// Witness key identifiers.
    pub witness_key_ids: Vec<String>,
    /// Cosignatures required, k of n.
    pub quorum: usize,
}

/// Per-scope-class policy. Every numeric field is optional at parse
/// time on purpose: absence is information, and the computation
/// raises [`InstitutioError::UnspecifiedBySpec`] when it reaches a
/// field it needs and does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPolicy {
    /// Standing minted per unit of risk-weighted completed work.
    pub mint_rate: Option<u64>,
    /// Per-epoch mint cap for this class.
    pub mint_cap_per_epoch: Option<u64>,
    /// Decay half-life in seconds.
    pub half_life_seconds: Option<u64>,
    /// Hop attenuation factor, parts per million.
    pub hop_attenuation_ppm: Option<u64>,
    /// The base burn amount the multipliers multiply: the policy
    /// field `burn_unit` (Section 16.10, decision 1).
    pub burn_unit: Option<u64>,
    /// Burn multipliers by denial reason code (wire strings).
    pub burn_multipliers: BTreeMap<String, u64>,
    /// Reason codes treated as severe under invariant I5.
    pub severe_reason_codes: BTreeSet<String>,
    /// Fraction of a severe burn applied across correlated classes,
    /// parts per million.
    pub correlated_burn_fraction_ppm: Option<u64>,
    /// This class's own ceiling curve, overriding the policy-level
    /// curve for this class (Section 16.10, decision 21).
    pub ceiling_curve: Option<Vec<CeilingTier>>,
}

/// A parsed `standing_policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingPolicy {
    /// The policy version string, when present.
    pub version: Option<String>,
    /// Per-class policies by class name.
    pub scope_classes: BTreeMap<String, ClassPolicy>,
    /// Epoch length in seconds; `None` means a single epoch.
    pub epoch_seconds: Option<u64>,
    /// Scope classes whose mint requires a counterparty
    /// countersignature at full weight (invariant I4).
    pub countersign_required: BTreeSet<String>,
    /// Absolute per-epoch diversity cap per counterparty.
    pub diversity_cap_per_counterparty: Option<u64>,
    /// Absolute per-epoch diversity cap per task type.
    pub diversity_cap_per_task_type: Option<u64>,
    /// Diversity cap per counterparty as a fraction of the class
    /// mint cap, parts per million (Section 16.10, decision 8).
    pub diversity_fraction_per_counterparty_ppm: Option<u64>,
    /// Diversity cap per task type as a fraction of the class mint
    /// cap, parts per million (Section 16.10, decision 8).
    pub diversity_fraction_per_task_type_ppm: Option<u64>,
    /// Diversity cap per child subtree as a fraction of the class
    /// mint cap, parts per million (Section 16.10, decision 8).
    pub diversity_fraction_per_subtree_ppm: Option<u64>,
    /// The ceiling curve tiers, in the order the policy lists them.
    pub ceiling_curve: Option<Vec<CeilingTier>>,
    /// The witness policy, when the charter names one.
    pub witness_policy: Option<WitnessPolicy>,
    /// Charter inheritance factor for forked charters, parts per
    /// million (invariant I3). Parsed and carried; the receipt
    /// format defines no inheritance event in v0.1, so no
    /// computation consumes it yet.
    pub inheritance_factor_ppm: Option<u64>,
}

fn uint(value: &Value, field: &str) -> Result<Option<u64>> {
    match value.as_u64() {
        Some(n) => Ok(Some(n)),
        // Section 16.10, decision 24, row (c) (repair round 5,
        // fourth re-audit finding U3): a stated null is a
        // malformed value, never an absent field. This reader
        // once returned None for null class fields while the
        // Python parser errored, and the Python parser made the
        // opposite choice for countersign_policy; both stop.
        None if value.is_null() => Err(InstitutioError::PolicyInvalid(format!(
            "policy field {field} is stated as null; a stated null \
             is a malformed value, never an absent field \
             (Section 16.10 decision 24)"
        ))),
        None => Err(InstitutioError::PolicyInvalid(format!(
            "policy field {field} must be a non-negative integer"
        ))),
    }
}

fn get_uint(map: &serde_json::Map<String, Value>, field: &str) -> Result<Option<u64>> {
    match map.get(field) {
        None => Ok(None),
        Some(value) => uint(value, field),
    }
}

fn default_severe() -> BTreeSet<String> {
    ["revoked".to_string(), "scope".to_string()]
        .into_iter()
        .collect()
}

fn parse_class(name: &str, value: &Value) -> Result<ClassPolicy> {
    let map = value.as_object().ok_or_else(|| {
        InstitutioError::PolicyInvalid(format!("scope class {name} is not an object"))
    })?;
    // Section 16.10, decision 18 (repair round 3): diversity caps
    // live at standing_policy level only. The per-class form is a
    // parse error here, exactly as the Python prototype raises on
    // it; a placement one tree honours and the other ignores is a
    // silent fork in the one definition.
    if map.contains_key("diversity_caps") {
        return Err(InstitutioError::PolicyInvalid(format!(
            "scope class {name}: diversity_caps inside a scope class \
             is non-conforming; Section 16.10 decision 18 places \
             diversity_caps at the top level of standing_policy only"
        )));
    }
    // Section 16.10, decision 22: the countersign requirement is
    // stated only at the top level of standing_policy, under the
    // one field name countersign_policy.
    if map.contains_key("countersign_policy") || map.contains_key("countersign_required") {
        return Err(InstitutioError::PolicyInvalid(format!(
            "scope class {name}: the countersign requirement inside \
             a scope class is non-conforming; it is stated only at \
             the top level of standing_policy as countersign_policy \
             (Section 16.10 decision 22)"
        )));
    }
    let class_ceiling_curve = match map.get("ceiling_curve") {
        None => None,
        Some(curve) => Some(parse_ceiling_curve(curve)?),
    };
    let mut multipliers = BTreeMap::new();
    if let Some(raw_multipliers) = map.get("burn_multipliers") {
        let entries = raw_multipliers.as_object().ok_or_else(|| {
            InstitutioError::PolicyInvalid(format!(
                "scope class {name}: burn_multipliers must be an \
                 object by reason code"
            ))
        })?;
        for (code, amount) in entries {
            multipliers.insert(
                code.clone(),
                amount.as_u64().ok_or_else(|| {
                    InstitutioError::PolicyInvalid(format!(
                        "burn_multipliers[{code}] must be a non-negative integer"
                    ))
                })?,
            );
        }
    }
    // Section 16.10, decision 24, row (d) (repair round 5,
    // fourth re-audit finding U4): the spec-named field is
    // severe_reason_codes. The undocumented severe_codes alias
    // this parser once honoured, silently dropping its
    // non-string entries, is rejected; the Python parser reads
    // only the spec name and now rejects the alias too.
    if map.contains_key("severe_codes") {
        return Err(InstitutioError::PolicyInvalid(format!(
            "scope class {name}: severe_codes is not a conforming \
             field name; the field is severe_reason_codes \
             (Section 16.10 decision 24)"
        )));
    }
    let mut severe = default_severe();
    if let Some(raw_codes) = map.get("severe_reason_codes") {
        let codes = raw_codes.as_array().ok_or_else(|| {
            InstitutioError::PolicyInvalid(format!(
                "scope class {name}: severe_reason_codes must be \
                 an array of reason code strings"
            ))
        })?;
        let mut parsed = BTreeSet::new();
        for code in codes {
            parsed.insert(code.as_str().ok_or_else(|| {
                InstitutioError::PolicyInvalid(format!(
                    "scope class {name}: severe_reason_codes \
                     entries must be strings"
                ))
            })?.to_string());
        }
        severe = parsed;
    }
    let half_life_seconds = match get_uint(map, "half_life_seconds")? {
        Some(n) => Some(n),
        None => get_uint(map, "half_life")?,
    };
    let hop_attenuation_ppm = match get_uint(map, "hop_attenuation_ppm")? {
        Some(n) => Some(n),
        None => match map.get("hop_attenuation") {
            None => None,
            Some(Value::Number(n)) if n.as_u64() == Some(1) => Some(PPM),
            // Decision 6 admits the bare form only as the integer
            // 1. A bare 0 previously parsed as 0 ppm (re-audit
            // observation O2); it is now unspecified like every
            // other bare value.
            Some(_) => {
                return Err(InstitutioError::UnspecifiedBySpec(
                    UnspecifiedField::HopAttenuation,
                ))
            }
        },
    };
    Ok(ClassPolicy {
        mint_rate: get_uint(map, "mint_rate")?,
        mint_cap_per_epoch: get_uint(map, "mint_cap_per_epoch")?,
        half_life_seconds,
        hop_attenuation_ppm,
        burn_unit: get_uint(map, "burn_unit")?,
        burn_multipliers: multipliers,
        severe_reason_codes: severe,
        correlated_burn_fraction_ppm: get_uint(map, "correlated_burn_fraction_ppm")?,
        ceiling_curve: class_ceiling_curve,
    })
}

fn parse_ceiling_curve(value: &Value) -> Result<Vec<CeilingTier>> {
    let tiers = value.as_array().ok_or_else(|| {
        InstitutioError::PolicyInvalid("ceiling_curve must be an array of tiers".into())
    })?;
    let mut out = Vec::new();
    for tier in tiers {
        let map = tier.as_object().ok_or_else(|| {
            InstitutioError::PolicyInvalid("ceiling_curve tier is not an object".into())
        })?;
        let need = |field: &str| -> Result<u64> {
            map.get(field).and_then(Value::as_u64).ok_or_else(|| {
                InstitutioError::PolicyInvalid(format!(
                    "ceiling_curve tier is missing integer field {field}"
                ))
            })
        };
        out.push(CeilingTier {
            min_standing: need("min_standing")?,
            max_budget_per_action: need("max_budget_per_action")?,
            max_budget_per_epoch: need("max_budget_per_epoch")?,
            max_irreversibility: need("max_irreversibility")?,
            max_data_sensitivity: need("max_data_sensitivity")?,
            max_delegation_depth: need("max_delegation_depth")?,
            max_fanout: need("max_fanout")?,
        });
    }
    Ok(out)
}

impl StandingPolicy {
    /// Parse a `standing_policy` JSON value. Absent optional fields
    /// stay absent; see the module documentation for the rule.
    pub fn from_value(value: &Value) -> Result<Self> {
        let map = value.as_object().ok_or_else(|| {
            InstitutioError::PolicyInvalid("standing_policy is not an object".into())
        })?;
        let classes_value = map.get("scope_classes").cloned().unwrap_or(Value::Null);
        let classes_map = classes_value.as_object().ok_or(
            InstitutioError::UnspecifiedBySpec(UnspecifiedField::ScopeClassesEncoding),
        )?;
        let mut scope_classes = BTreeMap::new();
        for (name, class_value) in classes_map {
            scope_classes.insert(name.clone(), parse_class(name, class_value)?);
        }
        // Section 16.10, decision 22 (repair round 4): the
        // countersign requirement has ONE encoding, the object
        // {"required_for": [class names]}, the only key it may
        // carry. Every other shape is a parse error here, never
        // silently honoured and never silently ignored: a bare
        // boolean or array, another inner form, or a differently
        // named field (countersign_required, at policy level or
        // inside a class, where parse_class also rejects it).
        // The third re-audit (finding T1) found this tree reading
        // four sub-forms while the Python tree read a differently
        // named field, each ignoring the other's.
        if map.contains_key("countersign_required") {
            return Err(InstitutioError::PolicyInvalid(
                "countersign_required is not a conforming field name; \
                 the countersign requirement is stated only as \
                 countersign_policy (Section 16.10 decision 22)"
                    .into(),
            ));
        }
        let mut countersign_required = BTreeSet::new();
        if let Some(countersign) = map.get("countersign_policy") {
            let object = countersign.as_object().ok_or_else(|| {
                InstitutioError::PolicyInvalid(
                    "countersign_policy must be an object of exactly \
                     the form {\"required_for\": [scope class names]} \
                     (Section 16.10 decision 22)"
                        .into(),
                )
            })?;
            if object.len() != 1 || !object.contains_key("required_for") {
                return Err(InstitutioError::PolicyInvalid(
                    "countersign_policy must carry required_for and \
                     no other key (Section 16.10 decision 22)"
                        .into(),
                ));
            }
            let list = object
                .get("required_for")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    InstitutioError::PolicyInvalid(
                        "countersign_policy required_for must be an \
                         array of scope class name strings \
                         (Section 16.10 decision 22)"
                            .into(),
                    )
                })?;
            for entry in list {
                let name = entry.as_str().ok_or_else(|| {
                    InstitutioError::PolicyInvalid(
                        "countersign_policy required_for entries \
                         must be scope class name strings \
                         (Section 16.10 decision 22)"
                            .into(),
                    )
                })?;
                countersign_required.insert(name.to_string());
            }
        }
        let mut diversity_cap_per_counterparty = None;
        let mut diversity_cap_per_task_type = None;
        let mut diversity_fraction_per_counterparty_ppm = None;
        let mut diversity_fraction_per_task_type_ppm = None;
        let mut diversity_fraction_per_subtree_ppm = None;
        if let Some(caps) = map.get("diversity_caps") {
            // A stated diversity_caps that is null or not an
            // object is malformed, never silently skipped
            // (decision 24, row (c)).
            let object = caps.as_object().ok_or_else(|| {
                InstitutioError::PolicyInvalid(
                    "diversity_caps must be a JSON object".into(),
                )
            })?;
            {
                // Section 16.10, decision 8: the fraction forms are
                // the three named parts-per-million fields. Any
                // other fraction-shaped key is an encoding the
                // decision does not admit.
                for key in object.keys() {
                    if key.contains("fraction")
                        && !matches!(
                            key.as_str(),
                            "per_counterparty_fraction_ppm"
                                | "per_task_type_fraction_ppm"
                                | "per_subtree_fraction_ppm"
                        )
                    {
                        return Err(InstitutioError::UnspecifiedBySpec(
                            UnspecifiedField::DiversityCapEncoding,
                        ));
                    }
                }
                diversity_cap_per_counterparty =
                    get_uint(object, "per_counterparty_per_epoch")?;
                diversity_cap_per_task_type = get_uint(object, "per_task_type_per_epoch")?;
                diversity_fraction_per_counterparty_ppm =
                    get_uint(object, "per_counterparty_fraction_ppm")?;
                diversity_fraction_per_task_type_ppm =
                    get_uint(object, "per_task_type_fraction_ppm")?;
                diversity_fraction_per_subtree_ppm =
                    get_uint(object, "per_subtree_fraction_ppm")?;
            }
        }
        let ceiling_curve = match map.get("ceiling_curve") {
            None => None,
            Some(value) => Some(parse_ceiling_curve(value)?),
        };
        // Section 16.10, decision 15 fixes the witness policy
        // encoding as exactly {witness_key_ids, quorum}. A
        // malformed witness policy is a parse error (third
        // re-audit minor t6, repair round 4): no "k" alias, no
        // missing-quorum default, no dropped non-string ids.
        // Decision 15's bounds on the quorum itself are checked
        // in validate_policy.
        let witness_policy = match map.get("witness_policy") {
            None => None,
            Some(witness) => {
                let object = witness.as_object().ok_or_else(|| {
                    InstitutioError::PolicyInvalid(
                        "witness_policy must be an object of exactly \
                         the form {witness_key_ids, quorum} \
                         (Section 16.10 decision 15)"
                            .into(),
                    )
                })?;
                if object.len() != 2
                    || !object.contains_key("witness_key_ids")
                    || !object.contains_key("quorum")
                {
                    return Err(InstitutioError::PolicyInvalid(
                        "witness_policy must carry witness_key_ids \
                         and quorum and no other key (Section 16.10 \
                         decision 15)"
                            .into(),
                    ));
                }
                let items = object
                    .get("witness_key_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        InstitutioError::PolicyInvalid(
                            "witness_policy witness_key_ids must be \
                             an array of key identifier strings \
                             (Section 16.10 decision 15)"
                                .into(),
                        )
                    })?;
                let mut ids = Vec::new();
                for item in items {
                    let id = item.as_str().ok_or_else(|| {
                        InstitutioError::PolicyInvalid(
                            "witness_policy witness_key_ids entries \
                             must be strings (Section 16.10 \
                             decision 15)"
                                .into(),
                        )
                    })?;
                    ids.push(id.to_string());
                }
                let quorum = object
                    .get("quorum")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        InstitutioError::PolicyInvalid(
                            "witness_policy quorum must be a \
                             non-negative integer (Section 16.10 \
                             decision 15)"
                                .into(),
                        )
                    })? as usize;
                Some(WitnessPolicy {
                    witness_key_ids: ids,
                    quorum,
                })
            }
        };
        let version = match map.get("standing_policy_version") {
            None => None,
            Some(value) => Some(value.as_str().ok_or_else(|| {
                InstitutioError::PolicyInvalid(
                    "standing_policy_version must be a string".into(),
                )
            })?.to_string()),
        };
        Ok(StandingPolicy {
            version,
            scope_classes,
            epoch_seconds: get_uint(map, "epoch_seconds")?,
            countersign_required,
            diversity_cap_per_counterparty,
            diversity_cap_per_task_type,
            diversity_fraction_per_counterparty_ppm,
            diversity_fraction_per_task_type_ppm,
            diversity_fraction_per_subtree_ppm,
            ceiling_curve,
            witness_policy,
            inheritance_factor_ppm: get_uint(map, "inheritance_factor_ppm")?,
        })
    }

    /// The epoch a timestamp falls in. A policy with no epoch length
    /// is a single epoch, numbered 0.
    pub fn epoch_of(&self, timestamp: i64) -> i64 {
        match self.epoch_seconds {
            Some(seconds) if seconds > 0 => timestamp.div_euclid(seconds as i64),
            _ => 0,
        }
    }
}

/// Validate a parsed policy for internal consistency. Returns every
/// problem found. The checks with specification force are: the
/// ceiling curve is a tier array with unique `min_standing` values,
/// an entry tier at 0, and non-decreasing ceilings (Section 16.10,
/// decision 10); the hop factor is greater than zero and at most
/// one (decision 6); the epoch length, when present, is at least
/// one second (decision 3); diversity fractions and the reserved
/// inheritance factor are within their parts-per-million ranges
/// (decisions 8 and 13); and, where the fields needed to judge it
/// are all present, a severe denial's first burn erases at least an
/// epoch of mint (invariant I5, decision 2), judged as
/// `burn_unit * burn_multipliers[severe] >= mint_cap_per_epoch`.
pub fn validate_policy(policy: &StandingPolicy) -> Vec<String> {
    let mut errors = Vec::new();
    if policy.scope_classes.is_empty() {
        errors.push("standing_policy names no scope_classes".into());
    }
    if policy.epoch_seconds == Some(0) {
        errors.push("epoch_seconds must be at least 1 when present".into());
    }
    if let Some(factor) = policy.inheritance_factor_ppm {
        if factor >= PPM {
            errors.push(
                "inheritance_factor_ppm must be below 1,000,000 (a factor below one)".into(),
            );
        }
    }
    for (field, value) in [
        ("per_counterparty_fraction_ppm", policy.diversity_fraction_per_counterparty_ppm),
        ("per_task_type_fraction_ppm", policy.diversity_fraction_per_task_type_ppm),
        ("per_subtree_fraction_ppm", policy.diversity_fraction_per_subtree_ppm),
    ] {
        if let Some(ppm) = value {
            if ppm > PPM {
                errors.push(format!(
                    "diversity_caps {field} is {ppm}, above 1,000,000 parts per million"
                ));
            }
        }
    }
    for (name, class) in &policy.scope_classes {
        if let Some(ppm) = class.hop_attenuation_ppm {
            if ppm == 0 || ppm > PPM {
                errors.push(format!(
                    "scope class {name}: hop_attenuation must be greater than zero and at most one"
                ));
            }
        }
        if let Some(half_life) = class.half_life_seconds {
            if half_life == 0 {
                errors.push(format!(
                    "scope class {name}: half_life must be at least one second"
                ));
            }
        }
        if let (Some(cap), Some(unit)) = (class.mint_cap_per_epoch, class.burn_unit) {
            for code in &class.severe_reason_codes {
                if let Some(multiplier) = class.burn_multipliers.get(code) {
                    if unit.saturating_mul(*multiplier) < cap {
                        errors.push(format!(
                            "scope class {name}: severe burn for {code} is {unit} * {multiplier}, below the epoch mint cap {cap}; invariant I5 requires one severe incident to erase at least an epoch of mint"
                        ));
                    }
                }
            }
        }
    }
    if let Some(curve) = &policy.ceiling_curve {
        let mut sorted: Vec<&CeilingTier> = curve.iter().collect();
        sorted.sort_by_key(|t| t.min_standing);
        if !sorted.iter().any(|t| t.min_standing == 0) {
            errors.push(
                "ceiling_curve has no entry tier: no tier with min_standing 0".into(),
            );
        }
        for pair in sorted.windows(2) {
            if pair[0].min_standing == pair[1].min_standing {
                errors.push(format!(
                    "ceiling_curve has two tiers at min_standing {}",
                    pair[0].min_standing
                ));
            }
        }
        for pair in sorted.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let monotone = b.max_budget_per_action >= a.max_budget_per_action
                && b.max_budget_per_epoch >= a.max_budget_per_epoch
                && b.max_irreversibility >= a.max_irreversibility
                && b.max_data_sensitivity >= a.max_data_sensitivity
                && b.max_delegation_depth >= a.max_delegation_depth
                && b.max_fanout >= a.max_fanout;
            if !monotone {
                errors.push(
                    "ceiling_curve is not monotone: a higher Standing tier lowers a ceiling"
                        .into(),
                );
            }
        }
    }
    if let Some(witness) = &policy.witness_policy {
        if witness.quorum == 0 || witness.quorum > witness.witness_key_ids.len() {
            errors.push(format!(
                "witness_policy quorum {} is outside 1..={}",
                witness.quorum,
                witness.witness_key_ids.len()
            ));
        }
    }
    errors
}

/// Structural validation used by charter validation, where the
/// policy arrives as raw JSON inside a charter. Lighter than
/// [`validate_policy`]: it checks the shape a charter must have, not
/// every consistency rule, and it tolerates absent optional fields
/// for the same reason [`StandingPolicy::from_value`] does.
pub fn validate_policy_structure(value: &Value) -> Vec<String> {
    match StandingPolicy::from_value(value) {
        Ok(policy) => {
            let mut errors = validate_policy(&policy);
            errors.retain(|e| {
                e.contains("names no scope_classes")
                    || e.contains("hop_attenuation")
                    || e.contains("half_life")
                    || e.contains("ceiling_curve")
                    || e.contains("witness_policy")
            });
            errors
        }
        Err(e) => vec![e.to_string()],
    }
}

//! Typed errors for institutio-core.
//!
//! Author: Gavin Blacklock
//!
//! The variant that matters most here is
//! [`InstitutioError::UnspecifiedBySpec`]. Specification
//! Section 16.10 (the encoding amendment of 2026-11-23) fixes every
//! encoding and parameter Section 16 once left open, and assigns
//! each charter-variable value to a named `standing_policy` field.
//! Where the computation reaches a value Section 16.10 requires
//! the policy to supply and the policy does not supply it, this
//! crate stops with that typed error instead of inventing a
//! number. The closed gap list, each item citing its Section 16.10
//! decision, lives in the crate README.

use std::fmt;

/// A Standing parameter or encoding that neither the specification
/// text nor the charter's `standing_policy` supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnspecifiedField {
    /// `mint_rate` for a scope class (specification Section 16.3
    /// names the field; a policy that omits it cannot mint).
    MintRate(String),
    /// `mint_cap_per_epoch` for a scope class, required as the
    /// denominator when a diversity cap is stated in the fraction
    /// form (Section 16.10, decision 8).
    MintCapPerEpoch(String),
    /// The base a burn multiplier multiplies: the policy field
    /// `burn_unit`, named by Section 16.10, decision 1.
    BurnUnit,
    /// A `burn_multipliers` entry for the reason code encountered.
    BurnMultiplier(String),
    /// The decay half-life for a scope class: the policy field
    /// `half_life_seconds` (Section 16.10, decision 4; the bare
    /// `half_life` name is a deprecated alias read as seconds).
    HalfLife(String),
    /// The hop attenuation factor in its float-free encoding: the
    /// policy field `hop_attenuation_ppm`, parts per million
    /// (Section 16.10, decision 6).
    HopAttenuation,
    /// The fraction of a severe burn applied across correlated
    /// classes: the policy field `correlated_burn_fraction_ppm`,
    /// required when a severe denial is processed (Section 16.10,
    /// decision 7).
    CorrelatedBurnFraction,
    /// The `ceiling_curve` mapping Standing to ceilings, in the
    /// tier-array encoding of Section 16.10, decision 10; a
    /// checkpoint cannot be built without it.
    CeilingCurve,
    /// A `diversity_caps` encoding Section 16.10, decision 8, does
    /// not admit (for example a fraction field that is not one of
    /// the three named parts-per-million fields).
    DiversityCapEncoding,
    /// The encoding of `scope_classes`: Section 16.10, decision 9,
    /// fixes the map form, class name to class policy object. This
    /// error means the policy omitted the classes or used another
    /// form.
    ScopeClassesEncoding,
    /// The witness policy (quorum and witness key list) required to
    /// judge a checkpoint's cosignatures (invariant I8).
    WitnessPolicy,
}

impl fmt::Display for UnspecifiedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnspecifiedField::MintRate(c) => write!(f, "mint_rate for scope class {c}"),
            UnspecifiedField::MintCapPerEpoch(c) => {
                write!(f, "mint_cap_per_epoch for scope class {c}")
            }
            UnspecifiedField::BurnUnit => write!(f, "burn_unit (the base burn_multipliers multiply)"),
            UnspecifiedField::BurnMultiplier(c) => {
                write!(f, "burn_multipliers entry for reason code {c}")
            }
            UnspecifiedField::HalfLife(c) => write!(f, "half_life for scope class {c}"),
            UnspecifiedField::HopAttenuation => {
                write!(f, "hop_attenuation in parts per million")
            }
            UnspecifiedField::CorrelatedBurnFraction => {
                write!(f, "correlated burn fraction for severe denials")
            }
            UnspecifiedField::CeilingCurve => write!(f, "ceiling_curve"),
            UnspecifiedField::DiversityCapEncoding => {
                write!(f, "diversity_caps in a form Section 16.10.8 admits")
            }
            UnspecifiedField::ScopeClassesEncoding => {
                write!(f, "scope_classes as a map of class name to class policy")
            }
            UnspecifiedField::WitnessPolicy => write!(f, "witness_policy"),
        }
    }
}

/// Errors of institutio-core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstitutioError {
    /// A charter failed validation; carries every error found, in
    /// the Python prototype's message wording where a corresponding
    /// check exists there.
    CharterInvalid(Vec<String>),
    /// A `standing_policy` is present but internally inconsistent
    /// (for example a severe burn multiplier that cannot erase an
    /// epoch of mint, against invariant I5).
    PolicyInvalid(String),
    /// The specification and the policy together do not determine a
    /// value the computation needs. See the module documentation.
    UnspecifiedBySpec(UnspecifiedField),
    /// A charter hash or checkpoint recomputation does not match.
    RecomputationMismatch(String),
    /// A signature does not verify, or is from the wrong key.
    SignatureInvalid(String),
    /// A signature's claimed key id is not in the pinned trust set,
    /// or the key material presented for it differs from the pinned
    /// key. Verification never takes its key from the untrusted
    /// document itself (re-audit finding N1, the charter form of
    /// audit finding C1).
    UntrustedKey(String),
    /// Checked integer arithmetic overflowed. Overflow is an error,
    /// never a wrap (engineering blueprint rule D4).
    Overflow,
    /// An error carried up from acta-core.
    Acta(String),
}

impl InstitutioError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            InstitutioError::CharterInvalid(_) => "CHARTER_INVALID",
            InstitutioError::PolicyInvalid(_) => "POLICY_INVALID",
            InstitutioError::UnspecifiedBySpec(_) => "UNSPECIFIED_BY_SPEC",
            InstitutioError::RecomputationMismatch(_) => "RECOMPUTATION_MISMATCH",
            InstitutioError::SignatureInvalid(_) => "SIGNATURE_INVALID",
            InstitutioError::UntrustedKey(_) => "UNTRUSTED_KEY",
            InstitutioError::Overflow => "OVERFLOW",
            InstitutioError::Acta(_) => "ACTA_ERROR",
        }
    }
}

impl fmt::Display for InstitutioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstitutioError::CharterInvalid(errors) => {
                write!(f, "CHARTER_INVALID: {}", errors.join("; "))
            }
            InstitutioError::PolicyInvalid(s) => write!(f, "POLICY_INVALID: {s}"),
            InstitutioError::UnspecifiedBySpec(field) => {
                write!(f, "UNSPECIFIED_BY_SPEC: {field}")
            }
            InstitutioError::RecomputationMismatch(s) => {
                write!(f, "RECOMPUTATION_MISMATCH: {s}")
            }
            InstitutioError::SignatureInvalid(s) => {
                write!(f, "SIGNATURE_INVALID: {s}")
            }
            InstitutioError::UntrustedKey(s) => {
                write!(f, "UNTRUSTED_KEY: {s}")
            }
            InstitutioError::Overflow => write!(f, "OVERFLOW: checked arithmetic overflowed"),
            InstitutioError::Acta(s) => write!(f, "ACTA_ERROR: {s}"),
        }
    }
}

impl std::error::Error for InstitutioError {}

impl From<acta_core::ActaError> for InstitutioError {
    fn from(error: acta_core::ActaError) -> Self {
        InstitutioError::Acta(error.to_string())
    }
}

/// Result alias used throughout institutio-core.
pub type Result<T> = std::result::Result<T, InstitutioError>;

//! institutio-core: the Institutio charter, ComputeStanding, and
//! Standing checkpoints.
//!
//! Author: Gavin Blacklock
//!
//! This crate implements specification Section 6 (the charter),
//! Section 7's Standing ground (the KILL-BURN checkpoint), and
//! Section 16 (Standing: Receipt-Minted Authority), on top of
//! acta-core and nothing else. The dependency runs one way:
//! institutio-core uses acta-core; acta-core never depends on
//! institutio-core.
//!
//! [`standing::compute_standing`] is the one definition of
//! ComputeStanding in this workspace. It is written from the
//! specification text, including the Section 16.10 encoding
//! amendment that closed the fifteen gaps the first build of this
//! crate found, and not from the Python prototype's provisional
//! parameter defaults. It stops with
//! [`InstitutioError::UnspecifiedBySpec`] wherever the charter's
//! `standing_policy` does not supply a value Section 16.10
//! requires the policy itself to state. The closed gap list, each
//! item citing its deciding clause, is in the crate README.
//!
//! Determinism rules, as in acta-core: integer arithmetic only, no
//! floating point, sorted maps wherever iteration order could
//! matter, no wall clock, no randomness in normative code.

#![deny(missing_docs)]

pub mod charter;
pub mod checkpoint;
pub mod error;
pub mod policy;
pub mod standing;

pub use charter::{
    compute_charter_hash, example_charter, scope_exceeds, scope_subset_errors, sign_charter,
    validate_charter, validate_charter_chain, validate_charter_structure, verify_charter,
    CHARTER_PAYLOAD_TYPE, CHARTER_VERSION,
};
pub use checkpoint::{
    build_checkpoint, standing_policy_hash, verify_checkpoint, CheckpointVerdict,
    StandingCheckpoint, CHECKPOINT_PAYLOAD_TYPE,
};
pub use error::{InstitutioError, Result, UnspecifiedField};
pub use policy::{validate_policy, CeilingTier, ClassPolicy, StandingPolicy, WitnessPolicy};
pub use standing::{
    ceilings_for_standing, compute_standing, counterparty_outcome_bytes, countersign_outcome,
    effective_authority, Ceilings, ClassStanding, StandingReceipt, COUNTERPARTY_PAYLOAD_TYPE,
};

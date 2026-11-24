//! Charter validation, attenuation, hash chain, and signing tests.
//!
//! Author: Gavin Blacklock

use acta_core::{Ed25519Signer, TrustSet};
use institutio_core::charter::{
    compute_charter_hash, example_charter, sign_charter, validate_charter,
    validate_charter_chain, validate_charter_structure, verify_charter,
};
use institutio_core::InstitutioError;
use serde_json::json;
use std::collections::BTreeSet;

fn founder_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("founder-root-key-1", &[5u8; 32])
}

fn founder_trust() -> TrustSet {
    TrustSet::from_signer(&founder_signer())
}

fn founder_set() -> BTreeSet<String> {
    BTreeSet::from(["founder-root-key-1".to_string()])
}

fn has_error(errors: &[String], needle: &str) -> bool {
    errors.iter().any(|e| e.contains(needle))
}

#[test]
fn example_charter_is_valid() {
    let errors = validate_charter_structure(&example_charter());
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn amendment_chain_links_by_hash() {
    let signer = founder_signer();
    let founding = sign_charter(&example_charter(), &signer).unwrap();
    let mut amendment_doc = example_charter();
    amendment_doc["org"]["name"] = json!("Example Firm, Amended");
    amendment_doc["predecessor_charter_hash"] =
        json!(compute_charter_hash(&founding).unwrap());
    let amendment = sign_charter(&amendment_doc, &signer).unwrap();
    let errors = validate_charter_chain(
        &[founding.clone(), amendment],
        &founder_trust(),
        &founder_set(),
    );
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");

    let mut broken_doc = example_charter();
    broken_doc["predecessor_charter_hash"] = json!("0".repeat(64));
    let broken = sign_charter(&broken_doc, &signer).unwrap();
    let errors = validate_charter_chain(
        &[founding.clone(), broken],
        &founder_trust(),
        &founder_set(),
    );
    assert!(has_error(&errors, "amendment chain is broken"), "{errors:?}");

    let mut founding_doc = example_charter();
    founding_doc["predecessor_charter_hash"] =
        json!(compute_charter_hash(&founding).unwrap());
    let founding_with_predecessor = sign_charter(&founding_doc, &signer).unwrap();
    let errors = validate_charter_chain(
        &[founding_with_predecessor],
        &founder_trust(),
        &founder_set(),
    );
    assert!(
        has_error(&errors, "founding charter must not name a predecessor"),
        "{errors:?}"
    );
}

#[test]
fn child_wider_than_parent_manifest_fails() {
    // The charter fixture's attack (prototype fixture 05): a child
    // manifest granting `exec` under a parent that grants no `exec`.
    let mut charter = example_charter();
    charter["authority_manifests"].as_array_mut().unwrap().push(json!({
        "manifest_id": "m-operator-helper-wide",
        "grantor_seat": "operator", "grantee_seat": "helper",
        "parent_manifest_id": "m-founder-operator",
        "scope": {"tools": ["read", "write", "exec"],
                  "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"external_calls": 2, "spend_units": 10}},
        "issued_at": 1763900200, "expires_at": 1766500000,
        "sub_delegation_allowed": false
    }));
    let errors = validate_charter_structure(&charter);
    assert!(has_error(&errors, "exceeds parent"), "{errors:?}");
}

#[test]
fn manifest_wider_than_grantor_seat_fails() {
    let mut charter = example_charter();
    charter["authority_manifests"].as_array_mut().unwrap().push(json!({
        "manifest_id": "m-helper-overreach",
        "grantor_seat": "helper", "grantee_seat": "operator",
        "scope": {"tools": ["read", "write"],
                  "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"external_calls": 2, "spend_units": 10}},
        "issued_at": 1763900200, "expires_at": 1766500000,
        "sub_delegation_allowed": false
    }));
    let errors = validate_charter_structure(&charter);
    assert!(
        has_error(&errors, "scope vs grantor seat helper"),
        "{errors:?}"
    );
}

#[test]
fn uncapped_child_limit_fails() {
    let mut charter = example_charter();
    let manifests = charter["authority_manifests"].as_array_mut().unwrap();
    manifests[1]["scope"]["limits"] = json!({"external_calls": 2});
    let errors = validate_charter_structure(&charter);
    assert!(has_error(&errors, "sets no cap"), "{errors:?}");
}

#[test]
fn delegation_loop_fails() {
    let mut charter = example_charter();
    let manifests = charter["authority_manifests"].as_array_mut().unwrap();
    manifests.push(json!({
        "manifest_id": "m-loop-a",
        "grantor_seat": "founder", "grantee_seat": "operator",
        "parent_manifest_id": "m-loop-b",
        "scope": {"tools": ["read"], "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"external_calls": 2, "spend_units": 10}},
        "issued_at": 1763900200, "expires_at": 1766500000,
        "sub_delegation_allowed": true
    }));
    manifests.push(json!({
        "manifest_id": "m-loop-b",
        "grantor_seat": "operator", "grantee_seat": "helper",
        "parent_manifest_id": "m-loop-a",
        "scope": {"tools": ["read"], "resources": ["repo"],
                  "operations": ["call"],
                  "limits": {"external_calls": 2, "spend_units": 10}},
        "issued_at": 1763900300, "expires_at": 1766500000,
        "sub_delegation_allowed": true
    }));
    let errors = validate_charter_structure(&charter);
    assert!(has_error(&errors, "delegation loop"), "{errors:?}");
}

#[test]
fn expiry_must_follow_issue() {
    let mut charter = example_charter();
    charter["authority_manifests"][0]["expires_at"] = json!(1763900000);
    let errors = validate_charter_structure(&charter);
    assert!(
        has_error(&errors, "expires_at must be after issued_at"),
        "{errors:?}"
    );
}

#[test]
fn unknown_recovery_seat_fails() {
    let mut charter = example_charter();
    charter["kill_switch"]["recovery_seat"] = json!("ghost");
    let errors = validate_charter_structure(&charter);
    assert!(
        has_error(&errors, "kill_switch: unknown recovery seat ghost"),
        "{errors:?}"
    );
}

#[test]
fn signed_charter_verifies_and_tamper_fails() {
    let signer = founder_signer();
    let trust = founder_trust();
    let signed = sign_charter(&example_charter(), &signer).unwrap();
    assert!(validate_charter(&signed, &trust, &founder_set()).is_empty());
    verify_charter(&signed, &trust, Some("founder-root-key-1")).unwrap();
    verify_charter(&signed, &trust, Some("other-key")).unwrap_err();

    let mut tampered = signed.clone();
    tampered["org"]["name"] = json!("Mallory Firm");
    assert!(verify_charter(&tampered, &trust, Some("founder-root-key-1")).is_err());
    assert!(has_error(
        &validate_charter_structure(&tampered),
        "charter_hash does not match"
    ));
}

#[test]
fn test_n1_unsigned_charter_rejected() {
    // Finding N1: structural validity is not authentication. An
    // unsigned charter fails authenticated validation.
    let errors = validate_charter(&example_charter(), &founder_trust(), &founder_set());
    assert!(has_error(&errors, "not signed"), "{errors:?}");
    assert!(verify_charter(&example_charter(), &founder_trust(),
                           Some("founder-root-key-1")).is_err());
}

#[test]
fn test_n1_attacker_signed_charter_rejected() {
    // An attacker key that copies the founder key id signs the
    // charter and embeds its own verifying key in the envelope.
    // The pinned trust set governs: rejection as UNTRUSTED_KEY.
    let attacker = Ed25519Signer::from_seed("founder-root-key-1", &[6u8; 32]);
    let forged = sign_charter(&example_charter(), &attacker).unwrap();
    let errors = validate_charter(&forged, &founder_trust(), &founder_set());
    assert!(!errors.is_empty(), "{errors:?}");
    let error = verify_charter(&forged, &founder_trust(), Some("founder-root-key-1"))
        .unwrap_err();
    assert_eq!(error.code(), "UNTRUSTED_KEY", "{error}");
    assert!(matches!(error, InstitutioError::UntrustedKey(_)));
}

#[test]
fn test_n1_chain_frozen_field_rejected() {
    // The founding charter freezes kill_switch; an amendment that
    // rewrites it fails the chain, as does the two-step unfreeze
    // (the freeze list itself may only grow, finding M6).
    let signer = founder_signer();
    let founding = sign_charter(&example_charter(), &signer).unwrap();
    let mut amendment_doc = example_charter();
    amendment_doc["predecessor_charter_hash"] =
        json!(compute_charter_hash(&founding).unwrap());
    amendment_doc["kill_switch"]["recovery_seat"] = json!("operator");
    let amendment = sign_charter(&amendment_doc, &signer).unwrap();
    let errors = validate_charter_chain(
        &[founding.clone(), amendment],
        &founder_trust(),
        &founder_set(),
    );
    assert!(has_error(&errors, "frozen field"), "{errors:?}");

    let mut unfreeze_doc = example_charter();
    unfreeze_doc["predecessor_charter_hash"] =
        json!(compute_charter_hash(&founding).unwrap());
    unfreeze_doc["amendment"]["frozen_fields"] = json!([]);
    let unfreeze = sign_charter(&unfreeze_doc, &signer).unwrap();
    let errors = validate_charter_chain(
        &[founding, unfreeze],
        &founder_trust(),
        &founder_set(),
    );
    assert!(has_error(&errors, "frozen"), "{errors:?}");
}

#[test]
fn test_n1_required_fields_enforced() {
    // The authenticated validator enforces the required fields the
    // Python side enforces: standing_policy, anchoring, and
    // org.founded among them.
    let signer = founder_signer();
    for field in ["standing_policy", "anchoring"] {
        let mut charter = example_charter();
        charter.as_object_mut().unwrap().remove(field);
        let signed = sign_charter(&charter, &signer).unwrap();
        let errors = validate_charter(&signed, &founder_trust(), &founder_set());
        assert!(
            has_error(&errors, &format!("missing required field: {field}")),
            "{field}: {errors:?}"
        );
    }
    let mut charter = example_charter();
    charter["org"].as_object_mut().unwrap().remove("founded");
    let signed = sign_charter(&charter, &signer).unwrap();
    let errors = validate_charter(&signed, &founder_trust(), &founder_set());
    assert!(has_error(&errors, "founded"), "{errors:?}");
}

#[test]
fn test_s1_dotted_frozen_field_is_a_validation_error() {
    // Repair round 3, minor s1: a dotted frozen_fields entry once
    // froze nothing in either tree while reading as protection.
    // It is a validation error, as is a name that is not a
    // top-level charter field.
    let mut charter = example_charter();
    charter["amendment"]["frozen_fields"] =
        json!(["kill_switch.authorized_key_ids"]);
    let errors = validate_charter_structure(&charter);
    assert!(has_error(&errors, "frozen_fields"), "{errors:?}");

    let mut charter = example_charter();
    charter["amendment"]["frozen_fields"] = json!(["no_such_field"]);
    let errors = validate_charter_structure(&charter);
    assert!(has_error(&errors, "frozen_fields"), "{errors:?}");
}

#[test]
fn test_o1_example_charter_freezes_the_amendment_object() {
    // Re-audit 2 observation o1, spec Section 16.10 decision 20:
    // the shipped example freezes "amendment" itself, so the
    // authorised key set cannot rotate by amendment in it.
    let charter = example_charter();
    let frozen = charter["amendment"]["frozen_fields"]
        .as_array()
        .unwrap();
    assert!(
        frozen.iter().any(|f| f.as_str() == Some("amendment")),
        "{frozen:?}"
    );
    assert!(
        frozen.iter().any(|f| f.as_str() == Some("kill_switch")),
        "{frozen:?}"
    );
}

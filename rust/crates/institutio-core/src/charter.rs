//! The Institutio charter: `institutio.json` model, validation,
//! attenuation, and the charter hash chain.
//!
//! Author: Gavin Blacklock
//!
//! Implements specification Section 6.3 to 6.7, mirroring the Python
//! prototype (`code/institutio/charter.py`) check for check and, where
//! a corresponding check exists there, message for message, so a
//! verdict here and a verdict there are directly comparable.
//!
//! A charter is a JSON document (the specification names the file
//! `institutio.json`) carried in a signed DSSE-style envelope. The
//! charter hash is the SHA-256 of the canonical JSON of the charter
//! payload (every field except `charter_hash` and `envelope`), the
//! same canonical JSON acta-core's legacy module produces for the
//! prototype. Amendments form a hash chain: the founding charter
//! names no predecessor, and every later charter names the hash of
//! the charter it supersedes (Section 6.5).
//!
//! Scope representation, as in the prototype: a scope is an object
//! with three set dimensions (`tools`, `resources`, `operations`),
//! each a list of strings, and a `limits` dimension, a map of limit
//! name to integer maximum. Attenuation is checked dimension by
//! dimension: a child delegation wider than its parent manifest, its
//! grantor seat, or its grantee seat in any dimension fails.
//!
//! Authentication (re-audit finding N1): structural validation
//! alone authenticates nothing. [`validate_charter`] and
//! [`verify_charter`] verify the envelope signature against a
//! pinned [`TrustSet`] supplied by the caller, never against the
//! `verifying_key` carried inside the untrusted envelope, and a
//! chain is anchored on a caller-pinned founder key set, with each
//! amendment verified against the authorised set of its verified
//! predecessor. [`validate_charter_structure`] is the
//! unauthenticated structural check, named as such; it is used
//! only where authentication is genuinely out of scope (the
//! conformance runner's structural check of a prototype fixture,
//! whose expected verdict is a structural rejection).

use crate::error::{InstitutioError, Result};
use acta_core::legacy::canonical_json_bytes;
use acta_core::signing::{hex_encode, sha256, verify_ed25519};
use acta_core::{Ed25519Signer, Signer, TrustSet};
use base64::Engine;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Charter format version produced and accepted by this crate.
pub const CHARTER_VERSION: &str = "0.1";

/// DSSE payload type for charters.
pub const CHARTER_PAYLOAD_TYPE: &str = "application/vnd.institutio.charter.v0.1+json";

const SET_DIMENSIONS: [&str; 3] = ["tools", "resources", "operations"];
const ON_LIMIT_ACTIONS: [&str; 2] = ["refuse", "escalate"];

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn int(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Errors where a child scope exceeds a parent scope, dimension by
/// dimension. A child wider than its parent in any dimension is an
/// attenuation violation. Mirrors the prototype's
/// `scope_subset_errors`, including its rule that a parent limit the
/// child leaves uncapped is itself a violation.
pub fn scope_subset_errors(child: &Value, parent: &Value, where_: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if !child.is_object() || !parent.is_object() {
        return vec![format!("{where_}: scope must be a JSON object")];
    }
    // An unknown dimension in the child is never silently ignored:
    // a dimension this function does not compare cannot attenuate
    // (re-audit minor r6, by construction here as in the prototype).
    if let Some(child_map) = child.as_object() {
        for key in child_map.keys() {
            if !SET_DIMENSIONS.contains(&key.as_str()) && key != "limits" {
                errors.push(format!(
                    "{where_}: unknown scope dimension {key:?}; only tools, resources, operations and limits attenuate"
                ));
            }
        }
    }
    for dim in SET_DIMENSIONS {
        let child_values = string_set(child, dim);
        let parent_values = string_set(parent, dim);
        for value in &child_values {
            if !parent_values.contains(value) {
                errors.push(format!(
                    "{where_}: {dim} exceeds parent: {value:?} is not granted by the parent scope"
                ));
            }
        }
    }
    let empty = Map::new();
    let child_limits = child
        .get("limits")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let parent_limits = parent
        .get("limits")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for (name, parent_max) in parent_limits {
        let Some(parent_max) = parent_max.as_i64() else {
            // A boolean or otherwise non-integer parent limit is
            // malformed, not a cap of zero (re-audit minor r6).
            errors.push(format!(
                "{where_}: limit {name} must be a non-negative integer"
            ));
            continue;
        };
        match child_limits.get(name).and_then(Value::as_i64) {
            None => errors.push(format!(
                "{where_}: limits exceeds parent: parent caps {name} at {parent_max} but the child sets no cap"
            )),
            Some(child_max) if child_max > parent_max => errors.push(format!(
                "{where_}: limits exceeds parent: child cap for {name} is {child_max}, parent cap is {parent_max}"
            )),
            _ => {}
        }
    }
    for (name, value) in child_limits {
        match value.as_i64() {
            Some(v) if v >= 0 => {}
            _ => errors.push(format!(
                "{where_}: limit {name} must be a non-negative integer"
            )),
        }
    }
    errors
}

/// True when the child scope exceeds the parent scope anywhere.
pub fn scope_exceeds(child: &Value, parent: &Value) -> bool {
    !scope_subset_errors(child, parent, "scope").is_empty()
}

/// The signed and hashed view of a charter: every field except
/// `charter_hash` and `envelope`.
pub fn charter_payload(charter: &Value) -> Value {
    match charter {
        Value::Object(map) => {
            let kept: Map<String, Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "charter_hash" && k.as_str() != "envelope")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Value::Object(kept)
        }
        other => other.clone(),
    }
}

/// The charter hash: SHA-256 over the canonical JSON payload bytes.
pub fn compute_charter_hash(charter: &Value) -> Result<String> {
    let bytes = canonical_json_bytes(&charter_payload(charter))?;
    Ok(hex_encode(&sha256(&bytes)))
}

/// Return a copy of the charter with its hash and a DSSE envelope
/// signed by the given Ed25519 signer over the PAE of the exact
/// canonical payload bytes.
pub fn sign_charter(charter: &Value, signer: &Ed25519Signer) -> Result<Value> {
    let mut signed = charter.clone();
    let object = signed
        .as_object_mut()
        .ok_or_else(|| InstitutioError::CharterInvalid(vec!["charter is not a JSON object".into()]))?;
    object.remove("charter_hash");
    object.remove("envelope");
    let hash = compute_charter_hash(&signed)?;
    let payload = canonical_json_bytes(&charter_payload(&signed))?;
    let signature = signer.sign_pae(CHARTER_PAYLOAD_TYPE, &payload);
    let engine = base64::engine::general_purpose::STANDARD;
    let object = signed.as_object_mut().expect("checked above");
    object.insert("charter_hash".into(), Value::String(hash));
    object.insert(
        "envelope".into(),
        serde_json::json!({
            "payload_type": CHARTER_PAYLOAD_TYPE,
            "payload": engine.encode(&payload),
            "signatures": [{
                "key_id": signer.key_id(),
                "signature": engine.encode(&signature),
                "verifying_key": engine.encode(signer.verifying_key_bytes()),
            }],
        }),
    );
    Ok(signed)
}

/// The envelope payload bytes of a charter, after the payload
/// type and byte-exactness checks. Shared by the signature paths.
fn envelope_payload(charter: &Value) -> Result<Vec<u8>> {
    let envelope = charter
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            InstitutioError::SignatureInvalid("charter carries no envelope".into())
        })?;
    if envelope.get("payload_type").and_then(Value::as_str) != Some(CHARTER_PAYLOAD_TYPE) {
        return Err(InstitutioError::SignatureInvalid(
            "charter envelope payload_type is wrong".into(),
        ));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let payload = envelope
        .get("payload")
        .and_then(Value::as_str)
        .and_then(|b64| engine.decode(b64).ok())
        .ok_or_else(|| {
            InstitutioError::SignatureInvalid("charter envelope payload is not base64".into())
        })?;
    if payload != canonical_json_bytes(&charter_payload(charter))? {
        return Err(InstitutioError::SignatureInvalid(
            "charter envelope payload bytes do not match the charter fields".into(),
        ));
    }
    Ok(payload)
}

/// Signature errors of one charter against a pinned trust set and
/// an authorised key id set. Empty means a signature from an
/// authorised key id verifies under the PINNED key for that id
/// over the exact payload bytes. The `verifying_key` a signature
/// entry carries inside the envelope is never believed: where it
/// differs from the pinned key for its claimed id, that is an
/// error of its own (finding N1).
fn signature_errors(
    charter: &Value,
    trust: &TrustSet,
    authorized_key_ids: &BTreeSet<String>,
) -> Vec<String> {
    if charter.get("envelope").is_none() {
        return vec!["charter is not signed: no DSSE envelope".into()];
    }
    let payload = match envelope_payload(charter) {
        Ok(payload) => payload,
        Err(e) => return vec![e.to_string()],
    };
    let envelope = charter
        .get("envelope")
        .and_then(Value::as_object)
        .expect("checked above");
    let signatures = envelope
        .get("signatures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if signatures.is_empty() {
        return vec!["charter envelope carries no signatures".into()];
    }
    if authorized_key_ids.is_empty() {
        return vec![
            "the authorised key set for this charter is empty; no key is authorised, \
             and validation fails closed rather than falling back to a key set the \
             document declares for itself (re-audit finding C2)"
                .into(),
        ];
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let mut errors = Vec::new();
    let mut verified = false;
    for entry in &signatures {
        let key_id = entry.get("key_id").and_then(Value::as_str).unwrap_or("");
        if !authorized_key_ids.contains(key_id) {
            errors.push(format!(
                "charter signature from key {key_id:?} is not authorised for this charter"
            ));
            continue;
        }
        let Some(pinned) = trust.get(key_id) else {
            errors.push(format!(
                "charter signature claims key {key_id:?}, which is not in the pinned trust set"
            ));
            continue;
        };
        if let Some(carried) = entry.get("verifying_key").and_then(Value::as_str) {
            match engine.decode(carried) {
                Ok(bytes) if bytes == pinned.to_bytes().to_vec() => {}
                _ => errors.push(format!(
                    "charter envelope carries a verifying key for {key_id:?} that differs \
                     from the pinned key; the pinned key governs (finding N1)"
                )),
            }
        }
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .and_then(|b64| engine.decode(b64).ok());
        match signature {
            Some(sig) if verify_ed25519(pinned, CHARTER_PAYLOAD_TYPE, &payload, &sig) => {
                verified = true;
            }
            _ => errors.push(format!(
                "charter signature from key {key_id:?} does not verify under the pinned key"
            )),
        }
    }
    if verified {
        Vec::new()
    } else if errors.is_empty() {
        vec!["charter signature does not verify under any authorised key".into()]
    } else {
        errors
    }
}

/// Verify a signed charter against a pinned trust set: the
/// recorded hash matches the contents, the envelope carries the
/// exact payload bytes, and a signature from an authorised key
/// verifies under the pinned key for its id. When
/// `expected_key_id` is given, the authorised set is exactly that
/// key. The key inside the envelope is never trusted (finding N1).
pub fn verify_charter(
    charter: &Value,
    trust: &TrustSet,
    expected_key_id: Option<&str>,
) -> Result<()> {
    let recorded = text(charter, "charter_hash").ok_or_else(|| {
        InstitutioError::CharterInvalid(vec!["charter carries no charter_hash".into()])
    })?;
    if recorded != compute_charter_hash(charter)? {
        return Err(InstitutioError::CharterInvalid(vec![
            "charter_hash does not match the charter contents".into(),
        ]));
    }
    // No expected key means no key is authorised: the authorised
    // set is never read out of the charter being verified.
    let authorized: BTreeSet<String> = match expected_key_id {
        Some(id) => BTreeSet::from([id.to_string()]),
        None => BTreeSet::new(),
    };
    let errors = signature_errors(charter, trust, &authorized);
    if errors.is_empty() {
        return Ok(());
    }
    let untrusted = errors.iter().any(|e| {
        e.contains("not in the pinned trust set") || e.contains("differs from the pinned key")
    });
    let message = errors.join("; ");
    if untrusted {
        Err(InstitutioError::UntrustedKey(message))
    } else {
        Err(InstitutioError::SignatureInvalid(message))
    }
}

fn check_delegation_loops(manifests: &[Value], errors: &mut Vec<String>) {
    let by_id: BTreeMap<String, &Value> = manifests
        .iter()
        .filter_map(|m| text(m, "manifest_id").map(|id| (id.to_string(), m)))
        .collect();
    for manifest in manifests {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut node = Some(manifest);
        while let Some(current) = node {
            let Some(parent_id) = text(current, "parent_manifest_id") else {
                break;
            };
            if !seen.insert(parent_id.to_string()) {
                errors.push(format!(
                    "manifest {}: delegation loop through parent manifests",
                    text(manifest, "manifest_id").unwrap_or("?")
                ));
                break;
            }
            node = by_id.get(parent_id).copied();
        }
    }
    // Seat graph cycles: grantor -> grantee edges.
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for manifest in manifests {
        if let (Some(grantor), Some(grantee)) =
            (text(manifest, "grantor_seat"), text(manifest, "grantee_seat"))
        {
            graph
                .entry(grantor.to_string())
                .or_default()
                .push(grantee.to_string());
        }
    }
    fn visit(
        seat: &str,
        graph: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
        errors: &mut Vec<String>,
    ) {
        if visiting.contains(seat) {
            errors.push(format!("delegation loop involving seat {seat}"));
            return;
        }
        if done.contains(seat) {
            return;
        }
        visiting.insert(seat.to_string());
        if let Some(next) = graph.get(seat) {
            for nxt in next.clone() {
                visit(&nxt, graph, visiting, done, errors);
            }
        }
        visiting.remove(seat);
        done.insert(seat.to_string());
    }
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for seat in graph.keys().cloned().collect::<Vec<_>>() {
        visit(&seat, &graph, &mut visiting, &mut done, errors);
    }
}

/// Validate the STRUCTURE of one charter value: every check that
/// does not authenticate. Returns every error found, in the
/// prototype's wording where a corresponding check exists there.
/// An empty vector means the charter is structurally valid; it
/// says nothing about who signed it. Authentication lives in
/// [`validate_charter`] and [`verify_charter`] (finding N1).
pub fn validate_charter_structure(charter: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if !charter.is_object() {
        return vec!["charter is not a JSON object".into()];
    }
    for field in [
        "charter_version",
        "org",
        "seats",
        "authority_manifests",
        "budgets",
        "amendment",
        "succession",
        "kill_switch",
        "standing_policy",
        "anchoring",
    ] {
        if charter.get(field).is_none() {
            errors.push(format!("missing required field: {field}"));
        }
    }
    if !errors.is_empty() {
        return errors;
    }
    // Repair round 3, minor s1: a frozen_fields entry freezes the
    // top-level charter field of that name in the amendment chain
    // check, nothing else. A dotted entry such as
    // "kill_switch.authorized_key_ids", or a name that is not a
    // top-level charter field, silently froze nothing while
    // reading as protection; it is a validation error, mirroring
    // the Python prototype.
    if let Some(frozen) = charter
        .get("amendment")
        .and_then(|a| a.get("frozen_fields"))
        .and_then(Value::as_array)
    {
        for entry in frozen {
            match entry.as_str() {
                Some(name) if !name.contains('.') && charter.get(name).is_some() => {}
                Some(name) => errors.push(format!(
                    "frozen_fields entry {name:?} does not name a \
                     top-level charter field; dotted paths freeze \
                     nothing and are rejected, not silently honoured \
                     (finding s1)"
                )),
                None => errors.push(
                    "frozen_fields entries must be strings".into(),
                ),
            }
        }
    }
    let org = charter.get("org").cloned().unwrap_or(Value::Null);
    if !org.is_object()
        || ["name", "charter_id", "founder_key_id", "founded"]
            .iter()
            .any(|k| org.get(k).is_none())
    {
        errors.push(
            "org must carry name, charter_id, founder_key_id and founded".into(),
        );
    }

    let empty_vec: Vec<Value> = Vec::new();
    let seats_list = charter
        .get("seats")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let mut seats: BTreeMap<String, Value> = BTreeMap::new();
    for seat in seats_list {
        let Some(seat_id) = text(seat, "seat_id") else {
            errors.push("seat without a seat_id".into());
            continue;
        };
        if seats.contains_key(seat_id) {
            errors.push(format!("duplicate seat_id: {seat_id}"));
        }
        seats.insert(seat_id.to_string(), seat.clone());
        if seat.get("scope").is_none() {
            errors.push(format!("seat {seat_id}: missing scope"));
        }
    }
    for seat in seats_list {
        if let Some(reports_to) = text(seat, "reports_to") {
            if !seats.contains_key(reports_to) {
                errors.push(format!(
                    "seat {}: reports_to names unknown seat {reports_to}",
                    text(seat, "seat_id").unwrap_or("?")
                ));
            }
        }
    }

    let manifests = charter
        .get("authority_manifests")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let mut manifest_ids: BTreeSet<String> = BTreeSet::new();
    for manifest in manifests {
        match text(manifest, "manifest_id") {
            None => errors.push("authority manifest without a manifest_id".into()),
            Some(id) => {
                if !manifest_ids.insert(id.to_string()) {
                    errors.push(format!("duplicate manifest_id: {id}"));
                }
            }
        }
    }
    let by_id: BTreeMap<String, &Value> = manifests
        .iter()
        .filter_map(|m| text(m, "manifest_id").map(|id| (id.to_string(), m)))
        .collect();
    for manifest in manifests {
        let manifest_id = text(manifest, "manifest_id").unwrap_or("?");
        let grantor = text(manifest, "grantor_seat").unwrap_or("");
        let grantee = text(manifest, "grantee_seat").unwrap_or("");
        if !seats.contains_key(grantor) {
            errors.push(format!(
                "manifest {manifest_id}: unknown grantor seat {grantor}"
            ));
            continue;
        }
        let grantee_external = manifest
            .get("grantee_external")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !seats.contains_key(grantee) && !grantee_external {
            errors.push(format!(
                "manifest {manifest_id}: unknown grantee seat {grantee}"
            ));
        }
        let Some(scope) = manifest.get("scope") else {
            errors.push(format!("manifest {manifest_id}: missing scope"));
            continue;
        };
        errors.extend(scope_subset_errors(
            scope,
            seats.get(grantor).and_then(|s| s.get("scope")).unwrap_or(&Value::Null),
            &format!("manifest {manifest_id} scope vs grantor seat {grantor}"),
        ));
        if let Some(grantee_seat) = seats.get(grantee) {
            errors.extend(scope_subset_errors(
                scope,
                grantee_seat.get("scope").unwrap_or(&Value::Null),
                &format!("manifest {manifest_id} scope vs grantee seat {grantee}"),
            ));
        }
        let issued = int(manifest, "issued_at");
        if issued.is_none() {
            errors.push(format!(
                "manifest {manifest_id}: issued_at must be integer seconds"
            ));
        }
        if let Some(expires) = manifest.get("expires_at") {
            if !expires.is_null() {
                match (issued, expires.as_i64()) {
                    (Some(i), Some(e)) if e > i => {}
                    _ => errors.push(format!(
                        "manifest {manifest_id}: expires_at must be after issued_at"
                    )),
                }
            }
        }
        if let Some(parent_id) = text(manifest, "parent_manifest_id") {
            match by_id.get(parent_id) {
                None => errors.push(format!(
                    "manifest {manifest_id}: unknown parent manifest {parent_id}"
                )),
                Some(parent) => {
                    if parent
                        .get("sub_delegation_allowed")
                        .and_then(Value::as_bool)
                        != Some(true)
                    {
                        errors.push(format!(
                            "manifest {manifest_id}: parent manifest {parent_id} does not permit sub-delegation"
                        ));
                    }
                    if text(manifest, "grantor_seat") != text(parent, "grantee_seat") {
                        errors.push(format!(
                            "manifest {manifest_id}: grantor must be the grantee of its parent manifest {parent_id}"
                        ));
                    }
                    errors.extend(scope_subset_errors(
                        scope,
                        parent.get("scope").unwrap_or(&Value::Null),
                        &format!("manifest {manifest_id} scope vs parent manifest {parent_id}"),
                    ));
                }
            }
        }
    }
    check_delegation_loops(manifests, &mut errors);

    let budgets = charter
        .get("budgets")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let mut budget_ids: BTreeSet<String> = BTreeSet::new();
    for budget in budgets {
        let Some(budget_id) = text(budget, "budget_id") else {
            errors.push("budget without a budget_id".into());
            continue;
        };
        budget_ids.insert(budget_id.to_string());
        match budget.get("amount").and_then(Value::as_i64) {
            Some(a) if a >= 0 => {}
            _ => errors.push(format!(
                "budget {budget_id}: amount must be a non-negative integer"
            )),
        }
        if text(budget, "unit").is_none() {
            errors.push(format!("budget {budget_id}: missing unit"));
        }
        let on_limit = text(budget, "on_limit").unwrap_or("");
        if !ON_LIMIT_ACTIONS.contains(&on_limit) {
            errors.push(format!(
                "budget {budget_id}: on_limit must be one of {ON_LIMIT_ACTIONS:?}"
            ));
        }
        if let Some(seat_id) = text(budget, "seat_id") {
            if !seats.contains_key(seat_id) {
                errors.push(format!("budget {budget_id}: unknown seat {seat_id}"));
            }
        }
    }
    for manifest in manifests {
        if let Some(reference) = text(manifest, "budget_ref") {
            if !budget_ids.contains(reference) {
                errors.push(format!(
                    "manifest {}: budget_ref names unknown budget {reference}",
                    text(manifest, "manifest_id").unwrap_or("?")
                ));
            }
        }
    }

    let succession = charter.get("succession").cloned().unwrap_or(Value::Null);
    let entries: Vec<Value> = match &succession {
        Value::Array(items) => items.clone(),
        Value::Object(_) => succession
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    for entry in &entries {
        if let Some(seat) = text(entry, "seat") {
            if !seats.contains_key(seat) {
                errors.push(format!("succession: unknown seat {seat}"));
            }
        } else {
            errors.push("succession: unknown seat ".into());
        }
        if let Some(successor) = text(entry, "successor_seat") {
            if !seats.contains_key(successor) {
                errors.push(format!("succession: unknown successor seat {successor}"));
            }
        }
    }

    let kill_switch = charter.get("kill_switch").cloned().unwrap_or(Value::Null);
    let authorized = kill_switch
        .get("authorized_key_ids")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !kill_switch.is_object() || !authorized {
        errors.push("kill_switch must name at least one authorized key id".into());
    }
    if let Some(recovery) = text(&kill_switch, "recovery_seat") {
        if !seats.contains_key(recovery) {
            errors.push(format!("kill_switch: unknown recovery seat {recovery}"));
        }
    }

    if let Some(policy) = charter.get("standing_policy") {
        if !policy.is_null() {
            for error in crate::policy::validate_policy_structure(policy) {
                errors.push(format!("standing_policy: {error}"));
            }
        }
    }

    if charter.get("charter_hash").is_some() {
        match compute_charter_hash(charter) {
            Ok(computed) => {
                if text(charter, "charter_hash") != Some(computed.as_str()) {
                    errors.push("charter_hash does not match the charter contents".into());
                }
            }
            Err(e) => errors.push(format!("charter_hash cannot be recomputed: {e}")),
        }
    }
    errors
}

/// Validate one charter: structure, plus authentication of its
/// envelope signature against the pinned trust set and the
/// authorised key id set the CALLER supplies. For a founding
/// charter the caller supplies its pinned founder key set; the
/// charter's own declarations are never the anchor (findings N1
/// and C2). An empty vector means the charter is valid and
/// authenticated.
pub fn validate_charter(
    charter: &Value,
    trust: &TrustSet,
    authorized_key_ids: &BTreeSet<String>,
) -> Vec<String> {
    let mut errors = validate_charter_structure(charter);
    errors.extend(signature_errors(charter, trust, authorized_key_ids));
    errors
}

/// The fields a charter's amendment section froze, as a set.
fn frozen_fields_of(charter: &Value) -> BTreeSet<String> {
    charter
        .get("amendment")
        .map(|a| string_set(a, "frozen_fields"))
        .unwrap_or_default()
}

/// Validate a charter history: each charter structurally valid and
/// authenticated, hashes linked, frozen fields honoured. Charter 0
/// is verified against the caller-pinned `founder_authorized` set;
/// each amendment is verified against the authorised set declared
/// by its VERIFIED predecessor, with no fallback to the
/// amendment's own declarations when the predecessor's set is
/// empty (finding C2). The freeze is cumulative: the union of
/// every predecessor's `frozen_fields` binds every later charter,
/// the freeze list itself may only grow, and `org.founded` never
/// changes (finding M6). The founding charter carries no
/// `predecessor_charter_hash`; every later charter must name the
/// hash of the charter it supersedes (Section 6.5).
pub fn validate_charter_chain(
    charters: &[Value],
    trust: &TrustSet,
    founder_authorized: &BTreeSet<String>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut previous_hash: Option<String> = None;
    let mut frozen_union: BTreeSet<String> = BTreeSet::new();
    for (index, charter) in charters.iter().enumerate() {
        for error in validate_charter_structure(charter) {
            errors.push(format!("charter {index}: {error}"));
        }
        let authorized: BTreeSet<String> = if index == 0 {
            founder_authorized.clone()
        } else {
            charters[index - 1]
                .get("amendment")
                .map(|a| string_set(a, "authorized_key_ids"))
                .unwrap_or_default()
        };
        for error in signature_errors(charter, trust, &authorized) {
            errors.push(format!("charter {index}: {error}"));
        }
        let predecessor = text(charter, "predecessor_charter_hash");
        if index == 0 {
            if predecessor.is_some() {
                errors.push("charter 0: founding charter must not name a predecessor".into());
            }
        } else {
            if predecessor != previous_hash.as_deref() {
                errors.push(format!(
                    "charter {index}: predecessor_charter_hash does not match the hash of charter {}; the amendment chain is broken",
                    index - 1
                ));
            }
            let previous = &charters[index - 1];
            let current_payload = charter_payload(charter);
            let previous_payload = charter_payload(previous);
            for field in &frozen_union {
                if current_payload.get(field.as_str())
                    != previous_payload.get(field.as_str())
                {
                    errors.push(format!(
                        "charter {index}: frozen field {field:?} was rewritten by an amendment"
                    ));
                }
            }
            let current_frozen = frozen_fields_of(charter);
            let dropped: Vec<&String> = frozen_union
                .difference(&current_frozen)
                .collect();
            if !dropped.is_empty() {
                errors.push(format!(
                    "charter {index}: frozen_fields drops previously frozen fields {dropped:?}; the freeze list itself is frozen and may only grow"
                ));
            }
            let founded = |c: &Value| {
                c.get("org")
                    .and_then(|o| o.get("founded"))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            if founded(charter) != founded(previous) {
                errors.push(format!(
                    "charter {index}: org.founded changed; the founding fact is not amendable"
                ));
            }
        }
        frozen_union.extend(frozen_fields_of(charter));
        previous_hash = compute_charter_hash(charter).ok();
    }
    errors
}

/// A minimal valid charter, mirroring the Python prototype's
/// `example_charter`, used by tests.
pub fn example_charter() -> Value {
    serde_json::json!({
        "charter_version": CHARTER_VERSION,
        "org": {
            "name": "Example Firm",
            "charter_id": "org-example-0001",
            "founded": "2026-11-23",
            "founder_key_id": "founder-root-key-1"
        },
        "seats": [
            {
                "seat_id": "founder", "title": "Founder", "role": "root",
                "occupant_key_id": "founder-root-key-1", "reports_to": null,
                "scope": {
                    "tools": ["read", "write", "exec"],
                    "resources": ["repo", "ledger"],
                    "operations": ["call", "delegate", "revoke"],
                    "limits": {"external_calls": 100, "spend_units": 1000}
                }
            },
            {
                "seat_id": "operator", "title": "Operator", "role": "worker",
                "occupant_key_id": "operator-key-1", "reports_to": "founder",
                "scope": {
                    "tools": ["read", "write"],
                    "resources": ["repo"],
                    "operations": ["call", "delegate"],
                    "limits": {"external_calls": 10, "spend_units": 100}
                }
            },
            {
                "seat_id": "helper", "title": "Helper", "role": "worker",
                "occupant_key_id": "helper-key-1", "reports_to": "operator",
                "scope": {
                    "tools": ["read"],
                    "resources": ["repo"],
                    "operations": ["call"],
                    "limits": {"external_calls": 2, "spend_units": 10}
                }
            }
        ],
        "authority_manifests": [
            {
                "manifest_id": "m-founder-operator",
                "grantor_seat": "founder", "grantee_seat": "operator",
                "scope": {
                    "tools": ["read", "write"],
                    "resources": ["repo"],
                    "operations": ["call", "delegate"],
                    "limits": {"external_calls": 10, "spend_units": 100}
                },
                "issued_at": 1763900000, "expires_at": 1766500000,
                "sub_delegation_allowed": true, "budget_ref": "b-operator"
            },
            {
                "manifest_id": "m-operator-helper",
                "grantor_seat": "operator", "grantee_seat": "helper",
                "parent_manifest_id": "m-founder-operator",
                "scope": {
                    "tools": ["read"],
                    "resources": ["repo"],
                    "operations": ["call"],
                    "limits": {"external_calls": 2, "spend_units": 10}
                },
                "issued_at": 1763900100, "expires_at": 1766500000,
                "sub_delegation_allowed": false
            }
        ],
        "budgets": [
            {
                "budget_id": "b-operator", "seat_id": "operator",
                "amount": 100, "unit": "spend_units", "period": "day",
                "on_limit": "refuse"
            }
        ],
        "amendment": {
            "authorized_key_ids": ["founder-root-key-1"],
            "notice_period_seconds": 86400,
            // The amendment object itself is frozen (re-audit 2
            // observation o1, spec Section 16.10 decision 20): a
            // founder-signed amendment still cannot rewrite the
            // amendment rules, so the authorised key set cannot
            // rotate by amendment in this example. Founders who
            // want rotation leave "amendment" unfrozen and accept
            // that rotation is then founder-signed delegation.
            "frozen_fields": ["kill_switch", "amendment"]
        },
        "succession": [
            {"seat": "founder", "successor_seat": "operator",
             "trigger": "signed_succession_act"}
        ],
        "kill_switch": {
            "authorized_key_ids": ["founder-root-key-1"],
            "recovery_seat": "founder"
        },
        "standing_policy": {
            "standing_policy_version": "0.1",
            "epoch_seconds": 86400,
            "burn_unit": 5,
            "severe_reason_codes": ["revoked", "scope"],
            "scope_classes": {
                "default": {
                    "mint_rate": 1,
                    "mint_cap_per_epoch": 50,
                    "half_life_seconds": 604800,
                    "burn_multipliers": {"revoked": 10, "scope": 10}
                }
            }
        },
        "anchoring": {"mechanisms": ["rfc3161", "transparency-log"]}
    })
}

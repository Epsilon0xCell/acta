//! acta-verify: the Acta one-file offline verifier.
//!
//! Author: Gavin Blacklock
//!
//! Self-contained binary: no network access, no account. It
//! ingests a native receipt bundle (JSON transport wrapper around
//! deterministic CBOR payloads, see acta-core's bundle module),
//! verifies the hash chain, the DSSE envelope signatures over
//! their exact transmitted bytes against a PINNED TRUST SET, and
//! every DENIAL receipt's reason code, and prints one plain
//! verdict.
//!
//! The trust set is the operator's own input (audit finding C1):
//! a JSON file pinning the verifying keys the operator trusts,
//! `{"keys": [{"key_id": "...", "verifying_key_hex": "..."}]}`.
//! Signatures are believed only when they verify under the pinned
//! key for their key id; the key carried inside an envelope is
//! never trusted. Without --trust-file the verifier fails closed.
//!
//! Usage:
//!   acta-verify BUNDLE.json --trust-file TRUST.json
//!   acta-verify BUNDLE.json --trust-file TRUST.json \
//!       --expected-head HEX --expected-length N
//!
//! Exit code 0 means the bundle verified; 1 means it did not; 2 means
//! the invocation itself was malformed.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut bundle_path: Option<String> = None;
    let mut trust_path: Option<String> = None;
    let mut expected_head: Option<String> = None;
    let mut expected_length: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--trust-file" => {
                i += 1;
                trust_path = args.get(i).cloned();
            }
            "--expected-head" => {
                i += 1;
                expected_head = args.get(i).cloned();
            }
            "--expected-length" => {
                i += 1;
                expected_length = args.get(i).and_then(|v| v.parse().ok());
            }
            other if bundle_path.is_none() && !other.starts_with("--") => {
                bundle_path = Some(other.to_string());
            }
            other => {
                eprintln!("FAIL: unrecognised argument {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(bundle_path) = bundle_path else {
        eprintln!("usage: acta-verify BUNDLE.json --trust-file TRUST.json [--expected-head HEX] [--expected-length N]");
        return ExitCode::from(2);
    };
    let Some(trust_path) = trust_path else {
        eprintln!(
            "FAIL: --trust-file is required: signatures are verified only \
             against pinned keys, never against keys carried in the bundle"
        );
        return ExitCode::from(2);
    };
    let trust_text = match std::fs::read_to_string(&trust_path) {
        Ok(text) => text,
        Err(e) => {
            println!("FAIL: cannot read trust file: {e}");
            return ExitCode::from(1);
        }
    };
    let trust_value: serde_json::Value = match serde_json::from_str(&trust_text) {
        Ok(value) => value,
        Err(e) => {
            println!("FAIL: trust file is not valid JSON: {e}");
            return ExitCode::from(1);
        }
    };
    let trust = match acta_core::TrustSet::from_json(&trust_value) {
        Ok(trust) => trust,
        Err(e) => {
            println!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };
    let text = match std::fs::read_to_string(&bundle_path) {
        Ok(text) => text,
        Err(e) => {
            println!("FAIL: cannot read bundle: {e}");
            return ExitCode::from(1);
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            println!("FAIL: bundle is not valid JSON: {e}");
            return ExitCode::from(1);
        }
    };
    let receipts = match acta_core::bundle::bundle_from_json(&value) {
        Ok(receipts) => receipts,
        Err(e) => {
            println!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };
    match acta_core::verify_chain(
        &receipts,
        &trust,
        expected_head.as_deref(),
        expected_length,
    ) {
        Ok(verdict) => {
            println!(
                "PASS: chain verified: {} receipts, head {}",
                verdict.length, verdict.head
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

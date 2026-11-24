//! CLI regression tests for audit finding C1 (2026-11-23 repair).
//!
//! Author: Gavin Blacklock
//!
//! The shipped verifier must fail closed without a pinned trust
//! file, and must reject a bundle forged under an attacker key
//! that copies the expected key id string.

use acta_core::{
    build_receipt, Agent, Ed25519Signer, Effects, ReceiptDraft, ReceiptType, GENESIS_HASH,
};
use std::io::Write;
use std::process::Command;

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("acta-c1-{name}-{}.json", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    path
}

fn chain_json(signer: &Ed25519Signer) -> String {
    let key = signer.verifying_key_bytes().to_vec();
    let mut prior = GENESIS_HASH.to_string();
    let mut chain = Vec::new();
    for sequence in 0..3u64 {
        let draft = ReceiptDraft {
            receipt_id: format!("r-{sequence:04}"),
            receipt_type: ReceiptType::Action,
            sequence,
            timestamp: 1_763_900_000 + sequence as i64,
            delegator: "seat-founder".into(),
            agent: Agent {
                id: "agent-operator-1".into(),
                model: "model-x".into(),
                model_version: "1.0".into(),
            },
            scope_granted: "tools=[read];resources=[repo];ops=[call]".into(),
            action_name: "repo.read_file".into(),
            arguments_hash: "c".repeat(64),
            result_hash: "d".repeat(64),
            prior_receipt_hash: prior.clone(),
            effects: Effects::default(),
            reason_code: None,
            verdict: None,
        };
        let receipt = build_receipt(signer, key.clone(), draft).unwrap();
        prior = receipt.receipt_hash.clone();
        chain.push(receipt);
    }
    acta_core::bundle::bundle_to_json(&chain).to_string()
}

fn trust_json(signer: &Ed25519Signer) -> String {
    serde_json::json!({"keys": [{
        "key_id": "acta-test-key-1",
        "verifying_key_hex": acta_core::signing::hex_encode(
            &signer.verifying_key_bytes()),
    }]})
    .to_string()
}

#[test]
fn test_c1_cli_rejects_forged_bundle_and_requires_trust_file() {
    let real = Ed25519Signer::from_seed("acta-test-key-1", &[9u8; 32]);
    let attacker = Ed25519Signer::from_seed("acta-test-key-1", &[42u8; 32]);
    let forged_path = write_temp("forged", &chain_json(&attacker));
    let trust_path = write_temp("trust", &trust_json(&real));
    let binary = env!("CARGO_BIN_EXE_acta-verify");

    // Forged bundle plus the real pinned trust file: rejected.
    let output = Command::new(binary)
        .arg(&forged_path)
        .arg("--trust-file")
        .arg(&trust_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAIL"));

    // Genuine bundle without a trust file: fails closed (exit 2).
    let genuine_path = write_temp("genuine", &chain_json(&real));
    let output = Command::new(binary).arg(&genuine_path).output().unwrap();
    assert_eq!(output.status.code(), Some(2));

    // Genuine bundle with the pinned trust file: passes.
    let output = Command::new(binary)
        .arg(&genuine_path)
        .arg("--trust-file")
        .arg(&trust_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS"));

    std::fs::remove_file(forged_path).ok();
    std::fs::remove_file(trust_path).ok();
    std::fs::remove_file(genuine_path).ok();
}

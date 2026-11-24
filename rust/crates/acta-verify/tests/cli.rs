//! Integration test for the acta-verify binary.
//!
//! Author: Gavin Blacklock

use acta_core::{
    build_receipt, Agent, Ed25519Signer, Effects, ReceiptDraft, ReceiptType, GENESIS_HASH,
};
use std::io::Write;
use std::process::Command;

fn write_trust() -> std::path::PathBuf {
    let signer = Ed25519Signer::from_seed("acta-test-key-1", &[9u8; 32]);
    let trust = serde_json::json!({"keys": [{
        "key_id": "acta-test-key-1",
        "verifying_key_hex": acta_core::signing::hex_encode(
            &signer.verifying_key_bytes()),
    }]});
    let mut path = std::env::temp_dir();
    path.push(format!("acta-verify-trust-{}.json", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(trust.to_string().as_bytes()).unwrap();
    path
}

fn write_bundle(chain: &[acta_core::SignedReceipt]) -> std::path::PathBuf {
    let json = acta_core::bundle::bundle_to_json(chain);
    let mut path = std::env::temp_dir();
    path.push(format!("acta-verify-test-{}.json", std::process::id()));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(json.to_string().as_bytes()).unwrap();
    path
}

fn make_chain() -> Vec<acta_core::SignedReceipt> {
    let signer = Ed25519Signer::from_seed("acta-test-key-1", &[9u8; 32]);
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
        let receipt = build_receipt(&signer, key.clone(), draft).unwrap();
        prior = receipt.receipt_hash.clone();
        chain.push(receipt);
    }
    chain
}

#[test]
fn cli_accepts_valid_bundle_and_rejects_tampered() {
    let chain = make_chain();
    let path = write_bundle(&chain);
    let trust_path = write_trust();
    let binary = env!("CARGO_BIN_EXE_acta-verify");
    let output = Command::new(binary)
        .arg(&path)
        .arg("--trust-file")
        .arg(&trust_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "stdout: {}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS"));

    let mut tampered = chain.clone();
    tampered[1].envelope.payload[10] ^= 0x01;
    let tampered_path = write_bundle(&tampered);
    let output = Command::new(binary)
        .arg(&tampered_path)
        .arg("--trust-file")
        .arg(&trust_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAIL"));
    std::fs::remove_file(path).ok();
    std::fs::remove_file(tampered_path).ok();
    std::fs::remove_file(trust_path).ok();
}

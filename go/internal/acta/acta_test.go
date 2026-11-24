// Tests for the Acta core: PAE golden bytes, native Ed25519 chain
// signing and verification, and the failure codes of Section 3.
//
// Author: Gavin Blacklock
package acta

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"acta-go/internal/canon"
)

func TestPAEGolden(t *testing.T) {
	got := string(PAE("application/vnd.acta.receipt.v0.1+json", []byte("{}")))
	want := "DSSEv1 38 application/vnd.acta.receipt.v0.1+json 2 {}"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
	if got := string(PAE("", nil)); got != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE = %q", got)
	}
}

func buildChain(t *testing.T, priv ed25519.PrivateKey, keyID string) *canon.Value {
	t.Helper()
	sign := func(pt string, payload []byte) *canon.Value { return SignEd25519(keyID, priv, pt, payload) }
	fields := func(name string) *canon.Value {
		return canon.Obj(
			"delegator", canon.Str("seat-founder"),
			"agent", canon.Obj("id", canon.Str("agent-1"), "model", canon.Str("model-x"), "model_version", canon.Str("1.0")),
			"scope_granted", canon.Str("tools=[read];resources=[repo];ops=[call]"),
			"action", canon.Obj("name", canon.Str(name), "arguments_hash", canon.Str(SHA256Hex([]byte(name)))),
			"result_hash", canon.Str(SHA256Hex([]byte("result-"+name))),
			"effects", canon.Obj("artifacts_changed", canon.Arr(), "external_calls", canon.Arr(), "sub_delegations", canon.Arr()),
		)
	}
	r0 := Seal(BuildReceipt("r-1", "GRANT", 0, 1000, GenesisHash, fields("grant.delegate")), sign)
	prev := r0.Get("receipt_hash").Str
	r1 := Seal(BuildReceipt("r-2", "ACTION", 1, 1060, prev, fields("repo.read")), sign)
	return canon.Arr(r0, r1)
}

func TestNativeChainVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain := buildChain(t, priv, "key-1")
	head, err := VerifyChain(chain, &Ed25519Verifier{ID: "key-1", Key: pub}, "", 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if head != chain.Arr[1].Get("receipt_hash").Str {
		t.Fatalf("head mismatch")
	}
	if _, err := VerifyChain(chain, &Ed25519Verifier{ID: "key-1", Key: pub}, "00", 0); err == nil || !strings.Contains(err.Error(), "TRUNCATED") {
		t.Fatalf("expected TRUNCATED, got %v", err)
	}
}

func TestNativeChainTamperAndWrongKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain := buildChain(t, priv, "key-1")
	// Tamper with a field after sealing.
	bad := canon.Clone(chain.Arr[1])
	bad.Set("result_hash", canon.Str(SHA256Hex([]byte("other"))))
	if _, err := VerifyChain(canon.Arr(chain.Arr[0], bad), &Ed25519Verifier{ID: "key-1", Key: pub}, "", 0); err == nil || !strings.Contains(err.Error(), "TAMPERED") {
		t.Fatalf("expected TAMPERED, got %v", err)
	}
	// A chain signed under another key id fails as KEY_ID_MISMATCH
	// against the pinned key.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	chain2 := buildChain(t, priv2, "rogue")
	if _, err := VerifyChain(chain2, &Ed25519Verifier{ID: "key-1", Key: pub}, "", 0); err == nil || !strings.Contains(err.Error(), "KEY_ID_MISMATCH") {
		t.Fatalf("expected KEY_ID_MISMATCH, got %v", err)
	}
	// Reordering fails as REORDERED.
	if _, err := VerifyChain(canon.Arr(chain.Arr[1], chain.Arr[0]), &Ed25519Verifier{ID: "key-1", Key: pub}, "", 0); err == nil || !strings.Contains(err.Error(), "REORDERED") {
		t.Fatalf("expected REORDERED, got %v", err)
	}
	// No verifier fails closed.
	if _, err := VerifyChain(chain, nil, "", 0); err == nil || !strings.Contains(err.Error(), "VERIFIER_REQUIRED") {
		t.Fatalf("expected VERIFIER_REQUIRED, got %v", err)
	}
}

func TestLegacyHMACRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	sign := func(pt string, payload []byte) *canon.Value { return SignHMAC("k1", secret, pt, payload) }
	fields := canon.Obj("delegator", canon.Str("seat-founder"))
	r0 := Seal(BuildReceipt("r-1", "DENIAL", 0, 1000, GenesisHash, fields), sign)
	r0.Set("reason_code", canon.Str("scope"))
	// Re-seal after adding the reason code so the payload matches.
	r0 = Seal(r0.Without("envelope", "receipt_hash"), sign)
	if _, err := VerifyChain(canon.Arr(r0), &HMACVerifier{ID: "k1", Secret: secret}, "", 0); err != nil {
		t.Fatalf("legacy verify: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(r0.Get("envelope").Get("payload").Str)
	if !strings.Contains(string(raw), "\"receipt_id\":\"r-1\"") {
		t.Fatalf("payload is not canonical JSON: %s", raw)
	}
}

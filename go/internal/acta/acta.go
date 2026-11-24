// Package acta implements the Acta receipt core: DSSE-style typed
// envelopes verified over exact bytes (specification Section 2.2),
// the receipt hash chain (Section 3.2), and chain verification with
// the failure codes the shared fixture corpus states.
//
// Two signature paths exist. The native path is Ed25519 from the Go
// standard library, as the specification's key identity model
// (Section 3.7) requires. The legacy path verifies the prototype
// corpus format (canonical JSON payloads, HMAC-SHA256 placeholder
// signatures under a published test secret): it exists only so the
// corpus can be consumed unchanged, and it is labelled legacy
// wherever it appears. Semantics and verdicts are the conformance
// target on the legacy path, not bytes.
//
// Author: Gavin Blacklock
package acta

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"

	"acta-go/internal/canon"
)

// ReceiptPayloadType is the DSSE payload type of a v0.1 receipt.
const ReceiptPayloadType = "application/vnd.acta.receipt.v0.1+json"

// GenesisHash is the prior hash of the first receipt in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// DenialReasonCodes is the v0.1 reason code set (Section 3.5).
var DenialReasonCodes = map[string]bool{
	"revoked": true, "scope": true, "manifest-mismatch": true,
	"budget": true, "standing-ceiling": true,
}

// ReceiptTypes is the v0.1 receipt type set.
var ReceiptTypes = map[string]bool{
	"GRANT": true, "ACTION": true, "DENIAL": true, "BURN": true,
	"PROMOTION": true, "DEMOTION": true, "REVOCATION": true,
	"KILL-BURN": true,
}

// Error is a typed verification failure with a stable code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(code, format string, args ...interface{}) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// PAE returns the DSSE Pre-Auth-Encoding of a payload type and the
// exact payload bytes.
func PAE(payloadType string, payload []byte) []byte {
	out := []byte("DSSEv1 ")
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payload))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Verifier authenticates envelope signatures for one pinned key id.
type Verifier interface {
	KeyID() string
	// Verify checks sig over the PAE of payloadType and payload.
	Verify(payloadType string, payload, sig []byte) bool
}

// HMACVerifier is the legacy prototype path: HMAC-SHA256 under a
// shared secret, behind the same interface as the native path.
type HMACVerifier struct {
	ID     string
	Secret []byte
}

func (v *HMACVerifier) KeyID() string { return v.ID }

// Verify implements Verifier.
func (v *HMACVerifier) Verify(payloadType string, payload, sig []byte) bool {
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write(PAE(payloadType, payload))
	return hmac.Equal(mac.Sum(nil), sig)
}

// Ed25519Verifier is the native path: a pinned Ed25519 public key.
type Ed25519Verifier struct {
	ID  string
	Key ed25519.PublicKey
}

func (v *Ed25519Verifier) KeyID() string { return v.ID }

// Verify implements Verifier.
func (v *Ed25519Verifier) Verify(payloadType string, payload, sig []byte) bool {
	if len(v.Key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(v.Key, PAE(payloadType, payload), sig)
}

// SignEd25519 signs the PAE of a payload with an Ed25519 key and
// returns the envelope signature object.
func SignEd25519(keyID string, priv ed25519.PrivateKey, payloadType string, payload []byte) *canon.Value {
	sig := ed25519.Sign(priv, PAE(payloadType, payload))
	return canon.Obj(
		"key_id", canon.Str(keyID),
		"signature", canon.Str(base64.StdEncoding.EncodeToString(sig)),
	)
}

// SignHMAC is the legacy signing counterpart of HMACVerifier.
func SignHMAC(keyID string, secret []byte, payloadType string, payload []byte) *canon.Value {
	mac := hmac.New(sha256.New, secret)
	mac.Write(PAE(payloadType, payload))
	return canon.Obj(
		"key_id", canon.Str(keyID),
		"signature", canon.Str(base64.StdEncoding.EncodeToString(mac.Sum(nil))),
	)
}

// VerifyChain verifies a receipt chain segment (the receipts array
// of a bundle) against one pinned verifier. It returns the chain
// head on success. Checks run in the order the corpus states:
// duplicate identity, envelope type, payload integrity, key
// identity, signature, sequence, prior hash, receipt type and
// denial reason codes, then the expected head and length.
func VerifyChain(receipts *canon.Value, ver Verifier, expectedHead string, expectedLength int) (string, error) {
	if ver == nil {
		return "", fail("VERIFIER_REQUIRED", "chain verification requires a verifier")
	}
	if receipts == nil || receipts.Kind != canon.KindArray || len(receipts.Arr) == 0 {
		return "", fail("EMPTY_CHAIN", "a chain segment with no receipts verifies as nothing")
	}
	seen := map[string]bool{}
	prev := GenesisHash
	for i, r := range receipts.Arr {
		if r.Kind != canon.KindObject {
			return "", fail("INVALID_RECEIPT", "receipt at index %d is not an object", i)
		}
		idv := r.Get("receipt_id")
		if idv == nil || idv.Kind != canon.KindString {
			return "", fail("INVALID_RECEIPT", "receipt at index %d has no string receipt_id", i)
		}
		if seen[idv.Str] {
			return "", fail("DUPLICATE_RECEIPT_ID", "receipt_id %q appears twice in one chain", idv.Str)
		}
		seen[idv.Str] = true
		if !r.Has("receipt_version") {
			return "", fail("INVALID_RECEIPT", "receipt %q states no receipt_version", idv.Str)
		}
		env := r.Get("envelope")
		if env == nil || env.Kind != canon.KindObject {
			return "", fail("INVALID_ENVELOPE", "receipt %q carries no envelope", idv.Str)
		}
		pt := env.Get("payload_type").StrOr("")
		if pt != ReceiptPayloadType {
			return "", fail("INVALID_ENVELOPE", "receipt %q payload type %q is not the v0.1 receipt type", idv.Str, pt)
		}
		payloadB64 := env.Get("payload").StrOr("")
		payload, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			return "", fail("TAMPERED", "receipt %q payload is not valid base64", idv.Str)
		}
		body, err := canon.Parse(payload)
		if err != nil {
			return "", fail("TAMPERED", "receipt %q payload does not parse: %v", idv.Str, err)
		}
		if string(canon.Encode(body)) != string(payload) {
			return "", fail("TAMPERED", "receipt %q payload is not in canonical encoding", idv.Str)
		}
		outer := r.Without("envelope", "receipt_hash")
		if !canon.Equal(body, outer) {
			return "", fail("TAMPERED", "receipt %q payload does not match the receipt fields", idv.Str)
		}
		if got := SHA256Hex(payload); got != r.Get("receipt_hash").StrOr("") {
			return "", fail("TAMPERED", "receipt %q hash does not match its payload", idv.Str)
		}
		sigs := env.Get("signatures")
		if sigs == nil || sigs.Kind != canon.KindArray || len(sigs.Arr) == 0 {
			return "", fail("SIGNATURE_INVALID", "receipt %q carries no signature", idv.Str)
		}
		sig0 := sigs.Arr[0]
		if sig0.Get("key_id").StrOr("") != ver.KeyID() {
			return "", fail("KEY_ID_MISMATCH", "receipt %q is signed under key %q, not the pinned key %q", idv.Str, sig0.Get("key_id").StrOr(""), ver.KeyID())
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig0.Get("signature").StrOr(""))
		if err != nil || !ver.Verify(pt, payload, sigBytes) {
			return "", fail("SIGNATURE_INVALID", "receipt %q signature does not verify", idv.Str)
		}
		seq := r.Get("sequence")
		if seq == nil || seq.Kind != canon.KindInt || seq.Int != int64(i) {
			return "", fail("REORDERED", "receipt %q sequence does not match its position %d", idv.Str, i)
		}
		if r.Get("prior_receipt_hash").StrOr("") != prev {
			return "", fail("CHAIN_BREAK", "receipt %q prior hash does not extend the chain head", idv.Str)
		}
		rt := r.Get("receipt_type").StrOr("")
		if !ReceiptTypes[rt] {
			return "", fail("INVALID_RECEIPT", "receipt %q has unknown receipt type %q", idv.Str, rt)
		}
		if rt == "DENIAL" {
			rc := r.Get("reason_code")
			if rc == nil || rc.Kind != canon.KindString || !DenialReasonCodes[rc.Str] {
				return "", fail("DENIAL_REASON_MISSING", "receipt %q is a DENIAL without a reason code from the v0.1 set", idv.Str)
			}
		}
		prev = r.Get("receipt_hash").StrOr("")
	}
	if expectedLength > 0 && len(receipts.Arr) != expectedLength {
		return "", fail("TRUNCATED", "chain length %d does not match the expected length %d", len(receipts.Arr), expectedLength)
	}
	if expectedHead != "" && prev != expectedHead {
		return "", fail("TRUNCATED", "chain head does not match the expected head")
	}
	return prev, nil
}

// BuildReceipt assembles a receipt body (without envelope and hash)
// in canonical field order. Callers add the envelope with Seal.
func BuildReceipt(id, rtype string, seq int64, ts int64, prev string, fields *canon.Value) *canon.Value {
	r := canon.Clone(fields)
	r.Set("receipt_id", canon.Str(id))
	r.Set("receipt_type", canon.Str(rtype))
	r.Set("receipt_version", canon.Str("0.1"))
	r.Set("sequence", canon.Int(seq))
	r.Set("timestamp", canon.Int(ts))
	r.Set("prior_receipt_hash", canon.Str(prev))
	return r
}

// Seal computes the receipt hash over the canonical payload bytes
// and attaches a DSSE-style envelope signed by the given signing
// function (which receives the payload type and exact bytes).
func Seal(r *canon.Value, sign func(payloadType string, payload []byte) *canon.Value) *canon.Value {
	body := r.Without("envelope", "receipt_hash")
	payload := canon.Encode(body)
	out := canon.Clone(r)
	out.Set("receipt_hash", canon.Str(SHA256Hex(payload)))
	env := canon.Obj(
		"payload", canon.Str(base64.StdEncoding.EncodeToString(payload)),
		"payload_type", canon.Str(ReceiptPayloadType),
		"signatures", canon.Arr(sign(ReceiptPayloadType, payload)),
	)
	out.Set("envelope", env)
	return out
}

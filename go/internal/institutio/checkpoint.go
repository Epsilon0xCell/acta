// StandingCheckpoint build and verification (specification
// Sections 16.3 and 16.7). A checkpoint is a claim about a
// computation: verification recomputes every computed field from
// the receipt segment and rejects any difference, checks the
// integrity seal over the checkpoint core, and enforces the
// policy's witness quorum where one is set (invariant I8).
//
// On the legacy prototype path, witness and issuer signatures are
// HMAC-SHA256 under the shared fixture secret, exactly as the
// corpus states them; the native path uses Ed25519 keys pinned by
// the caller. The seal is unkeyed and detects naive tampering
// only; external reliance requires witness cosignatures.
//
// Author: Gavin Blacklock
package institutio

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"

	"acta-go/internal/acta"
	"acta-go/internal/canon"
)

// CheckpointPayloadType is the DSSE payload type of a checkpoint.
const CheckpointPayloadType = "application/vnd.institutio.checkpoint.v0.1+json"

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// ChainHeadOf returns the head hash of a plain receipt segment:
// the last receipt's own receipt_hash where it carries one,
// otherwise the SHA-256 of its canonical encoding.
func ChainHeadOf(receipts *canon.Value) string {
	if receipts == nil || receipts.Kind != canon.KindArray || len(receipts.Arr) == 0 {
		return acta.GenesisHash
	}
	last := receipts.Arr[len(receipts.Arr)-1]
	if h := last.Get("receipt_hash"); h != nil && h.Kind == canon.KindString {
		return h.Str
	}
	return sha256Hex(canon.Encode(last))
}

// checkpointCore builds the core object whose canonical encoding
// the integrity seal and the signatures cover: every checkpoint
// field except integrity_hash, checkpoint_sig and witness_cosigs.
func checkpointCore(cp *canon.Value) *canon.Value {
	return cp.Without("integrity_hash", "checkpoint_sig", "witness_cosigs")
}

// BuildCheckpoint computes a checkpoint for one agent from a
// receipt segment and a policy.
func BuildCheckpoint(receipts *canon.Value, policyRaw *canon.Value, evalTime *int64, agentID, orgID, charterHash string, counterpartyKeys map[string]ed25519.PublicKey) (*canon.Value, error) {
	pol, err := ParsePolicy(policyRaw)
	if err != nil {
		return nil, err
	}
	res, err := ComputeStanding(receipts, policyRaw, evalTime, agentID, counterpartyKeys)
	if err != nil {
		return nil, err
	}
	// Recompute the evaluation time and totals the same way the
	// computation saw them.
	var eval int64
	if evalTime != nil {
		eval = *evalTime
	} else {
		for _, rv := range receipts.Arr {
			if tv := rv.Get("timestamp"); tv != nil && tv.Kind == canon.KindInt && tv.Int > eval {
				eval = tv.Int
			}
		}
	}
	standingVector := canon.Obj()
	ceilingsVector := canon.Obj()
	denials := map[string]int64{}
	var mintTotal, burnTotal, decayTotal int64
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := res[n]
		standingVector.Set(n, canon.Int(r.Standing))
		ceilingsVector.Set(n, r.Ceilings.Value())
		mintTotal += r.Minted
		burnTotal += r.Burned
		decayTotal += r.DecayApplied
		for code, c := range r.DenialsByCode {
			denials[code] += c
		}
	}
	denialsVal := canon.Obj()
	codes := make([]string, 0, len(denials))
	for c := range denials {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		denialsVal.Set(c, canon.Int(denials[c]))
	}
	var epoch int64
	if pol.EpochSeconds != nil {
		epoch = eval / *pol.EpochSeconds
	}
	cp := canon.Obj(
		"agent_id", canon.Str(agentID),
		"org_id", canon.Str(orgID),
		"charter_hash", canon.Str(charterHash),
		"standing_policy_hash", canon.Str(pol.Hash()),
		"receipt_chain_head_hash", canon.Str(ChainHeadOf(receipts)),
		"epoch", canon.Int(epoch),
		"eval_time", canon.Int(eval),
		"standing_vector", standingVector,
		"ceilings_vector", ceilingsVector,
		"mint_total", canon.Int(mintTotal),
		"burn_total", canon.Int(burnTotal),
		"decay_applied", canon.Int(decayTotal),
		"denials_by_reason_code", denialsVal,
		"witness_cosigs", canon.Arr(),
		"checkpoint_sig", canon.Null,
	)
	cp.Set("integrity_hash", canon.Str(sha256Hex(canon.Encode(checkpointCore(cp)))))
	return cp, nil
}

// VerifyCheckpoint verifies a checkpoint against its receipt
// segment and policy. witnessVerifiers maps witness key ids to
// verifiers (legacy HMAC or native Ed25519); on the legacy path
// every witness shares the fixture secret, as the corpus states.
func VerifyCheckpoint(cp *canon.Value, receipts *canon.Value, policyRaw *canon.Value, counterpartyKeys map[string]ed25519.PublicKey, witnessVerifiers map[string]acta.Verifier) error {
	if cp == nil || cp.Kind != canon.KindObject {
		return perr("CHECKPOINT_INVALID", "checkpoint is not an object")
	}
	pol, err := ParsePolicy(policyRaw)
	if err != nil {
		return err
	}
	core := checkpointCore(cp)
	if got := sha256Hex(canon.Encode(core)); got != cp.Get("integrity_hash").StrOr("") {
		return perr("CHECKPOINT_INVALID", "checkpoint integrity hash does not match its core fields")
	}
	agentID := cp.Get("agent_id").StrOr("")
	evalV := cp.Get("eval_time")
	if evalV == nil || evalV.Kind != canon.KindInt {
		return perr("CHECKPOINT_INVALID", "checkpoint states no integer eval_time")
	}
	eval := evalV.Int
	rebuilt, err := BuildCheckpoint(receipts, policyRaw, &eval, agentID, cp.Get("org_id").StrOr(""), cp.Get("charter_hash").StrOr(""), counterpartyKeys)
	if err != nil {
		return err
	}
	for _, field := range []string{"agent_id", "org_id", "charter_hash", "standing_policy_hash", "receipt_chain_head_hash", "epoch", "eval_time", "standing_vector", "ceilings_vector", "mint_total", "burn_total", "decay_applied", "denials_by_reason_code"} {
		if !canon.Equal(rebuilt.Get(field), cp.Get(field)) {
			return perr("CHECKPOINT_INVALID", fmt.Sprintf("checkpoint %s does not match recomputation", field))
		}
	}
	if pol.Witness != nil {
		allowed := map[string]bool{}
		for _, id := range pol.Witness.KeyIDs {
			allowed[id] = true
		}
		count := 0
		seen := map[string]bool{}
		if cosigs := cp.Get("witness_cosigs"); cosigs != nil && cosigs.Kind == canon.KindArray {
			for _, cs := range cosigs.Arr {
				kid := cs.Get("key_id").StrOr("")
				if !allowed[kid] || seen[kid] {
					continue
				}
				ver, ok := witnessVerifiers[kid]
				if !ok {
					continue
				}
				sig, derr := decodeB64(cs.Get("signature").StrOr(""))
				if derr != nil || !ver.Verify(CheckpointPayloadType, canon.Encode(core), sig) {
					continue
				}
				seen[kid] = true
				count++
			}
		}
		if int64(count) < pol.Witness.Quorum {
			return perr("CHECKPOINT_INVALID", "witness quorum not met: %d valid witness cosignatures, quorum is %d", count, pol.Witness.Quorum)
		}
	}
	if sig := cp.Get("checkpoint_sig"); sig != nil && sig.Kind == canon.KindObject {
		kid := sig.Get("key_id").StrOr("")
		ver, ok := witnessVerifiers[kid]
		if !ok {
			return perr("CHECKPOINT_INVALID", "checkpoint issuer key %q is not pinned", kid)
		}
		sigBytes, derr := decodeB64(sig.Get("signature").StrOr(""))
		if derr != nil || !ver.Verify(CheckpointPayloadType, canon.Encode(core), sigBytes) {
			return perr("CHECKPOINT_INVALID", "checkpoint signature does not verify")
		}
	}
	return nil
}

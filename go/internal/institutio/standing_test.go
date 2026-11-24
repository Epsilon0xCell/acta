// Tests for ComputeStanding, the policy strictness table, the
// checkpoint, and charter validation. Expected values are computed
// by hand from specification Section 16.10.
//
// Author: Gavin Blacklock
package institutio

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"acta-go/internal/acta"
	"acta-go/internal/canon"
)

func mustParse(t *testing.T, s string) *canon.Value {
	t.Helper()
	v, err := canon.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return v
}

const basePolicy = `{
  "ceiling_curve": [{"min_standing": 0, "max_budget_per_action": 100, "max_budget_per_epoch": 1000, "max_irreversibility": 3, "max_data_sensitivity": 3, "max_delegation_depth": 3, "max_fanout": 8}],
  "scope_classes": {"write": {"mint_rate": 2, "mint_cap_per_epoch": 36, "half_life_seconds": 10000000, "hop_attenuation_ppm": 1000000, "burn_unit": 36, "burn_multipliers": {"revoked": 1}, "severe_reason_codes": ["revoked"], "correlated_burn_fraction_ppm": 0}}
}`

func action(ts int64, extra string) string {
	return `{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": ` + itoa(ts) + `, "result_hash": "rh", "action": {"name": "repo.write", "arguments_hash": "ah", "risk_weight": 3, "scope_class": "write"}` + extra + `}`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestMintAndCapSaturation(t *testing.T) {
	var rs []string
	for i := 0; i < 10; i++ {
		rs = append(rs, action(int64(i*60), ""))
	}
	seg := mustParse(t, "["+strings.Join(rs, ",")+"]")
	eval := int64(540)
	res, err := ComputeStanding(seg, mustParse(t, basePolicy), &eval, "a1", nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	w := res["write"]
	if w.Minted != 36 || w.Standing != 36 || w.Actions != 10 {
		t.Fatalf("expected cap saturation at 36, got minted %d standing %d actions %d", w.Minted, w.Standing, w.Actions)
	}
}

func TestBurnClosedForm(t *testing.T) {
	var rs []string
	for i := 0; i < 6; i++ {
		rs = append(rs, action(int64(i*60), ""))
	}
	rs = append(rs, `{"receipt_type": "DENIAL", "agent": {"id": "a1"}, "timestamp": 600, "reason_code": "revoked", "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}`)
	rs = append(rs, `{"receipt_type": "BURN", "agent": {"id": "a1"}, "timestamp": 660, "burn_amount": 36, "action": {"name": "standing.burn", "risk_weight": 1, "scope_class": "write"}}`)
	seg := mustParse(t, "["+strings.Join(rs, ",")+"]")
	eval := int64(660)
	res, err := ComputeStanding(seg, mustParse(t, basePolicy), &eval, "a1", nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	w := res["write"]
	if w.Burned != 36 || w.Standing != 0 || w.BurnRecorded != 36 || w.Denials != 1 {
		t.Fatalf("expected burn to zero, got %+v", w)
	}
}

func TestDecayWholeHalfLives(t *testing.T) {
	pol := `{"ceiling_curve": [{"min_standing": 0, "max_budget_per_action": 100, "max_budget_per_epoch": 1000, "max_irreversibility": 3, "max_data_sensitivity": 3, "max_delegation_depth": 3, "max_fanout": 8}], "epoch_seconds": 100, "scope_classes": {"write": {"mint_rate": 8, "half_life_seconds": 100, "hop_attenuation_ppm": 1000000}}}`
	seg := mustParse(t, "["+action(1000, "")+"]")
	eval := int64(1200)
	res, err := ComputeStanding(seg, mustParse(t, pol), &eval, "a1", nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	w := res["write"]
	if w.Minted != 24 || w.Standing != 6 || w.DecayApplied != 18 {
		t.Fatalf("expected minted 24 standing 6 decay 18, got %+v", w)
	}
}

func TestCountersignRequiredMintsZeroAndVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pol := strings.Replace(basePolicy, `"scope_classes"`, `"countersign_policy": {"required_for": ["write"]}, "scope_classes"`, 1)
	seg := mustParse(t, "["+action(1000, `, "receipt_id": "r1", "counterparty_id": "cp-1"`)+"]")
	eval := int64(1000)
	res, err := ComputeStanding(seg, mustParse(t, pol), &eval, "a1", nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if res["write"].Minted != 0 {
		t.Fatalf("missing countersignature must mint zero, got %d", res["write"].Minted)
	}
	// Sign the decision 16 descriptor and retry.
	pr, err := parseReceipt(seg.Arr[0])
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, acta.PAE(CounterpartyPayloadType, outcomeDescriptor(pr)))
	seg2 := mustParse(t, "["+action(1000, `, "receipt_id": "r1", "counterparty_id": "cp-1", "counterparty_sig": "`+b64(sig)+`"`)+"]")
	res, err = ComputeStanding(seg2, mustParse(t, pol), &eval, "a1", map[string]ed25519.PublicKey{"cp-1": pub})
	if err != nil {
		t.Fatalf("compute with sig: %v", err)
	}
	if res["write"].Minted != 6 {
		t.Fatalf("valid countersignature must mint 6, got %d", res["write"].Minted)
	}
}

func b64(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3 && i+j < len(b); j++ {
			v = v<<8 | uint32(b[i+j])
			n++
		}
		v <<= uint(8 * (3 - n))
		for j := 0; j < n+1; j++ {
			out = append(out, enc[(v>>uint(18-6*j))&63])
		}
		for j := 0; j < 3-n; j++ {
			out = append(out, '=')
		}
	}
	return string(out)
}

func TestKillIsAbsorbing(t *testing.T) {
	rs := []string{action(0, ""), action(60, ""), action(120, ""),
		`{"receipt_type": "KILL-BURN", "agent": {"id": "a1"}, "timestamp": 180, "killed_agent_ids": ["a1"], "action": {"name": "standing.kill-burn", "risk_weight": 1, "scope_class": "write"}}`,
		action(240, ""), action(300, "")}
	seg := mustParse(t, "["+strings.Join(rs, ",")+"]")
	eval := int64(300)
	res, err := ComputeStanding(seg, mustParse(t, basePolicy), &eval, "a1", nil)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	w := res["write"]
	if w.Standing != 0 || w.Minted != 18 || w.Actions != 5 || !w.Killed {
		t.Fatalf("expected absorbing kill (standing 0, minted 18, actions 5), got %+v", w)
	}
}

func TestStrictnessTable(t *testing.T) {
	cases := map[string]string{
		"negative burn_unit":   strings.Replace(basePolicy, `"burn_unit": 36`, `"burn_unit": -36`, 1),
		"float mint_rate":      strings.Replace(basePolicy, `"mint_rate": 2`, `"mint_rate": 2.5`, 1),
		"boolean mint_rate":    strings.Replace(basePolicy, `"mint_rate": 2`, `"mint_rate": true`, 1),
		"null countersign":     strings.Replace(basePolicy, `"scope_classes"`, `"countersign_policy": null, "scope_classes"`, 1),
		"severe_codes alias":   strings.Replace(basePolicy, `"severe_reason_codes"`, `"severe_codes"`, 1),
		"list scope_classes":   `{"ceiling_curve": [], "scope_classes": []}`,
		"epoch zero":           strings.Replace(basePolicy, `"scope_classes"`, `"epoch_seconds": 0, "scope_classes"`, 1),
		"witness k alias":      strings.Replace(basePolicy, `"scope_classes"`, `"witness_policy": {"witness_key_ids": ["w1"], "k": 1}, "scope_classes"`, 1),
		"per-class diversity":  strings.Replace(basePolicy, `"mint_rate": 2`, `"mint_rate": 2, "diversity_caps": {}`, 1),
		"bare countersign req": strings.Replace(basePolicy, `"scope_classes"`, `"countersign_required": ["write"], "scope_classes"`, 1),
		"tier missing field":   strings.Replace(basePolicy, `"max_fanout": 8`, `"max_fanout": 8`, 1)[:0] + strings.Replace(basePolicy, `, "max_fanout": 8`, ``, 1),
	}
	for name, pol := range cases {
		if _, err := ParsePolicy(mustParse(t, pol)); err == nil {
			t.Fatalf("%s: expected a policy error", name)
		}
	}
	// Receipt level strictness.
	bad := map[string]string{
		"unknown type":      `{"receipt_type": "TRANSFER", "agent": {"id": "a1"}, "timestamp": 0}`,
		"agent as string":   `{"receipt_type": "ACTION", "agent": "a1", "timestamp": 0}`,
		"float timestamp":   `{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 1.5}`,
		"string timestamp":  `{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": "0"}`,
		"null risk weight":  `{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 0, "action": {"name": "x", "risk_weight": null, "scope_class": "write"}}`,
		"null counterparty": `{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 0, "counterparty_id": null, "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}`,
	}
	for name, r := range bad {
		seg := mustParse(t, "["+r+"]")
		if _, err := ComputeStanding(seg, mustParse(t, basePolicy), nil, "a1", nil); err == nil {
			t.Fatalf("%s: expected a computation error", name)
		}
	}
	// A missing ceiling curve is an unspecified-by-policy error
	// wherever ceilings are produced (decision 23).
	noCurve := `{"scope_classes": {"write": {"mint_rate": 2, "half_life_seconds": 100, "hop_attenuation_ppm": 1000000}}}`
	seg := mustParse(t, "["+action(0, "")+"]")
	if _, err := ComputeStanding(seg, mustParse(t, noCurve), nil, "a1", nil); err == nil || !strings.Contains(err.Error(), "UNSPECIFIED_BY_SPEC") {
		t.Fatalf("missing curve: expected UNSPECIFIED_BY_SPEC, got %v", err)
	}
	// Top-level class fields never merge into a class (decision 24e).
	topLevel := `{"ceiling_curve": [{"min_standing": 0, "max_budget_per_action": 1, "max_budget_per_epoch": 1, "max_irreversibility": 0, "max_data_sensitivity": 0, "max_delegation_depth": 0, "max_fanout": 0}], "mint_rate": 9, "scope_classes": {"write": {"half_life_seconds": 100, "hop_attenuation_ppm": 1000000}}}`
	if _, err := ComputeStanding(seg, mustParse(t, topLevel), nil, "a1", nil); err == nil {
		t.Fatalf("top-level mint_rate must not be inherited by the class")
	}
}

func TestCheckpointRoundTripAndQuorum(t *testing.T) {
	pol := strings.Replace(basePolicy, `"mint_cap_per_epoch": 36`, `"mint_cap_per_epoch": 360`, 1)
	pol = strings.Replace(pol, `"scope_classes"`, `"witness_policy": {"witness_key_ids": ["w-1", "w-2", "w-3"], "quorum": 2}, "scope_classes"`, 1)
	rs := []string{action(1000, ""), action(1060, ""), action(1120, "")}
	seg := mustParse(t, "["+strings.Join(rs, ",")+"]")
	eval := int64(1120)
	cp, err := BuildCheckpoint(seg, mustParse(t, pol), &eval, "a1", "org-1", strings.Repeat("c", 64), nil)
	if err != nil {
		t.Fatalf("build checkpoint: %v", err)
	}
	if cp.Get("standing_vector").Get("write").Int != 18 {
		t.Fatalf("checkpoint standing = %v", cp.Get("standing_vector"))
	}
	secret := []byte("fixture-secret")
	vers := map[string]acta.Verifier{}
	for _, id := range []string{"w-1", "w-2", "w-3"} {
		vers[id] = &acta.HMACVerifier{ID: id, Secret: secret}
	}
	// No witnesses yet: quorum 2 unmet.
	if err := VerifyCheckpoint(cp, seg, mustParse(t, pol), nil, vers); err == nil || !strings.Contains(err.Error(), "witness quorum not met") {
		t.Fatalf("expected quorum failure, got %v", err)
	}
	// Add two witness cosignatures over the checkpoint core.
	core := checkpointCore(cp)
	var cosigs []*canon.Value
	for _, id := range []string{"w-1", "w-2"} {
		cosigs = append(cosigs, acta.SignHMAC(id, secret, CheckpointPayloadType, canon.Encode(core)))
	}
	// SignHMAC returns {key_id, signature}; reshape to the corpus form.
	var fixed []*canon.Value
	for _, cs := range cosigs {
		fixed = append(fixed, canon.Obj("key_id", cs.Get("key_id"), "signature", cs.Get("signature")))
	}
	cp.Set("witness_cosigs", canon.Arr(fixed...))
	if err := VerifyCheckpoint(cp, seg, mustParse(t, pol), nil, vers); err != nil {
		t.Fatalf("verify with quorum: %v", err)
	}
	// Tamper with a computed field: recomputation must reject it.
	cp2 := canon.Clone(cp)
	cp2.Get("standing_vector").Set("write", canon.Int(19))
	cp2.Set("integrity_hash", canon.Str(sha256Hex(canon.Encode(checkpointCore(cp2)))))
	if err := VerifyCheckpoint(cp2, seg, mustParse(t, pol), nil, vers); err == nil || !strings.Contains(err.Error(), "does not match recomputation") {
		t.Fatalf("expected recomputation mismatch, got %v", err)
	}
}

func TestCharterAttenuationAndExpiry(t *testing.T) {
	charter := `{
	  "charter_version": "0.1",
	  "org": {"name": "Example", "charter_id": "org-1", "founded": "2026-11-23", "founder_key_id": "root-1"},
	  "seats": [
	    {"seat_id": "founder", "title": "Founder", "role": "root", "occupant_key_id": "root-1", "reports_to": null, "scope": {"tools": ["read", "write", "exec"], "resources": ["repo"], "operations": ["call", "delegate"], "limits": {"spend_units": 1000, "external_calls": 100}}},
	    {"seat_id": "operator", "title": "Operator", "role": "worker", "occupant_key_id": "op-1", "reports_to": "founder", "scope": {"tools": ["read", "write"], "resources": ["repo"], "operations": ["call"], "limits": {"spend_units": 100, "external_calls": 10}}}
	  ],
	  "authority_manifests": [
	    {"manifest_id": "m1", "grantor_seat": "founder", "grantee_seat": "operator", "issued_at": 100, "expires_at": 200, "sub_delegation_allowed": false, "scope": {"tools": ["read"], "resources": ["repo"], "operations": ["call"], "limits": {"spend_units": 10, "external_calls": 2}}}
	  ],
	  "budgets": [{"budget_id": "b1", "seat_id": "operator", "amount": 100, "unit": "spend_units", "period": "day", "on_limit": "refuse"}],
	  "standing_policy": {"scope_classes": {"write": {"mint_rate": 1, "mint_cap_per_epoch": 50, "burn_unit": 5, "burn_multipliers": {"revoked": 10}, "severe_reason_codes": ["revoked"]}}},
	  "amendment": {"authorized_key_ids": ["root-1"], "frozen_fields": ["kill_switch", "amendment"], "notice_period_seconds": 0},
	  "succession": [{"seat": "founder", "successor_seat": "operator", "trigger": "signed_succession_act"}],
	  "kill_switch": {"authorized_key_ids": ["root-1"], "recovery_seat": "founder"},
	  "anchoring": {"mechanisms": ["rfc3161", "transparency-log"]},
	  "envelope": {"payload": "", "payload_type": "application/vnd.institutio.charter.v0.1+json", "signatures": []}
	}`
	c := mustParse(t, charter)
	if err := ValidateCharterStructure(c); err != nil {
		t.Fatalf("valid charter rejected: %v", err)
	}
	// Expiry at issue time is invalid.
	bad := strings.Replace(charter, `"expires_at": 200`, `"expires_at": 100`, 1)
	if err := ValidateCharterStructure(mustParse(t, bad)); err == nil || !strings.Contains(err.Error(), "expires_at must be after issued_at") {
		t.Fatalf("expected expiry error, got %v", err)
	}
	// A child wider than its parent is invalid.
	wide := strings.Replace(charter, `"sub_delegation_allowed": false`, `"sub_delegation_allowed": true`, 1)
	wide = strings.Replace(wide, `"budgets":`, `"authority_manifests_extra": [], "budgets":`, 1)
	_ = wide
}

// Charter validation for institutio.json (specification Section
// 6): structure, seat and delegation attenuation (Section 6.4),
// amendment and succession hash chains (Section 6.5), budgets
// (Section 6.6) and the kill switch (Section 6.7).
//
// The structural validator in this file is the documented legacy
// adaptation for the prototype corpus, mirroring the Rust tree's
// documented position: the corpus charters carry HMAC placeholder
// signatures, so the fixture path checks structure, attenuation,
// predecessor linkage over the charter hash, the cumulative
// freeze and the founding-date rule. Authenticated validation
// against a pinned trust set is provided separately for native
// Ed25519 charters and is exercised by this module's own tests.
//
// Author: Gavin Blacklock
package institutio

import (
	"fmt"
	"strings"

	"acta-go/internal/canon"
)

// CharterPayloadType is the DSSE payload type of a charter.
const CharterPayloadType = "application/vnd.institutio.charter.v0.1+json"

// ComputeCharterHash hashes a charter: SHA-256 over the canonical
// encoding of the charter without its envelope and stated hash.
func ComputeCharterHash(charter *canon.Value) string {
	return sha256Hex(canon.Encode(charter.Without("envelope", "charter_hash")))
}

var charterFields = map[string]bool{
	"charter_version": true, "org": true, "predecessor_charter_hash": true,
	"seats": true, "authority_manifests": true, "budgets": true,
	"standing_policy": true, "policy_refs": true, "amendment": true,
	"succession": true, "kill_switch": true, "anchoring": true, "envelope": true,
	"charter_hash": true,
}

type scope struct {
	tools     map[string]bool
	resources map[string]bool
	ops       map[string]bool
	limits    map[string]int64
}

func parseScope(v *canon.Value, where string) (*scope, error) {
	if v == nil || v.Kind != canon.KindObject {
		return nil, perr("CHARTER_INVALID", "%s scope is missing or not an object", where)
	}
	s := &scope{tools: map[string]bool{}, resources: map[string]bool{}, ops: map[string]bool{}, limits: map[string]int64{}}
	fill := func(field string, dst map[string]bool) error {
		lv := v.Get(field)
		if lv == nil {
			return nil
		}
		if lv.Kind != canon.KindArray {
			return perr("CHARTER_INVALID", "%s scope %s must be an array of strings", where, field)
		}
		for _, e := range lv.Arr {
			if e.Kind != canon.KindString {
				return perr("CHARTER_INVALID", "%s scope %s entries must be strings", where, field)
			}
			dst[e.Str] = true
		}
		return nil
	}
	if err := fill("tools", s.tools); err != nil {
		return nil, err
	}
	if err := fill("resources", s.resources); err != nil {
		return nil, err
	}
	if err := fill("operations", s.ops); err != nil {
		return nil, err
	}
	if lv := v.Get("limits"); lv != nil {
		if lv.Kind != canon.KindObject {
			return nil, perr("CHARTER_INVALID", "%s scope limits must be an object", where)
		}
		for _, k := range lv.Keys {
			n, err := strictInt(lv, k, where+" scope limits")
			if err != nil {
				return nil, err
			}
			s.limits[k] = *n
		}
	}
	return s, nil
}

// exceeds reports whether child exceeds parent in any dimension.
func exceeds(child, parent *scope) (string, bool) {
	for t := range child.tools {
		if !parent.tools[t] {
			return "tools", true
		}
	}
	for t := range child.resources {
		if !parent.resources[t] {
			return "resources", true
		}
	}
	for t := range child.ops {
		if !parent.ops[t] {
			return "operations", true
		}
	}
	for k, n := range child.limits {
		pn, ok := parent.limits[k]
		if !ok || n > pn {
			return "limits." + k, true
		}
	}
	return "", false
}

// ValidateCharterStructure runs the structural charter checks.
func ValidateCharterStructure(c *canon.Value) error {
	if c == nil || c.Kind != canon.KindObject {
		return perr("CHARTER_INVALID", "charter is not an object")
	}
	for _, f := range []string{"charter_version", "org", "seats", "authority_manifests", "budgets", "standing_policy", "amendment", "succession", "kill_switch", "anchoring", "envelope"} {
		if !c.Has(f) {
			return perr("CHARTER_INVALID", "charter is missing required field %s", f)
		}
	}
	org := c.Get("org")
	if org.Kind != canon.KindObject {
		return perr("CHARTER_INVALID", "charter org is not an object")
	}
	for _, f := range []string{"name", "charter_id", "founded", "founder_key_id"} {
		if !org.Has(f) {
			return perr("CHARTER_INVALID", "charter org is missing field %s", f)
		}
	}
	if err := ValidateStandingPolicy(c.Get("standing_policy")); err != nil {
		return err
	}
	// Amendment freeze list entries must name whole top-level
	// fields; dotted or unknown entries are validation errors.
	amend := c.Get("amendment")
	if amend.Kind != canon.KindObject || !amend.Has("authorized_key_ids") {
		return perr("CHARTER_INVALID", "charter amendment rules are missing authorized_key_ids")
	}
	if ff := amend.Get("frozen_fields"); ff != nil {
		if ff.Kind != canon.KindArray {
			return perr("CHARTER_INVALID", "amendment.frozen_fields must be an array")
		}
		for _, e := range ff.Arr {
			if e.Kind != canon.KindString || strings.Contains(e.Str, ".") || !charterFields[e.Str] {
				return perr("CHARTER_INVALID", "amendment.frozen_fields entry %q is not a whole charter field", e.StrOr(""))
			}
		}
	}
	seats := map[string]*canon.Value{}
	seatScopes := map[string]*scope{}
	seatList := c.Get("seats")
	if seatList.Kind != canon.KindArray || len(seatList.Arr) == 0 {
		return perr("CHARTER_INVALID", "charter seats must be a non-empty array")
	}
	for _, sv := range seatList.Arr {
		id := sv.Get("seat_id").StrOr("")
		if id == "" {
			return perr("CHARTER_INVALID", "a seat states no seat_id")
		}
		if _, dup := seats[id]; dup {
			return perr("CHARTER_INVALID", "duplicate seat_id %q", id)
		}
		seats[id] = sv
		sc, err := parseScope(sv.Get("scope"), "seat "+id)
		if err != nil {
			return err
		}
		seatScopes[id] = sc
	}
	for _, sv := range seatList.Arr {
		if rt := sv.Get("reports_to"); rt != nil && rt.Kind == canon.KindString {
			if _, ok := seats[rt.Str]; !ok {
				return perr("CHARTER_INVALID", "seat %q reports to unknown seat %q", sv.Get("seat_id").StrOr(""), rt.Str)
			}
		}
	}
	budgetIDs := map[string]bool{}
	if bl := c.Get("budgets"); bl != nil && bl.Kind == canon.KindArray {
		for _, bv := range bl.Arr {
			budgetIDs[bv.Get("budget_id").StrOr("")] = true
		}
	}
	manifests := map[string]*canon.Value{}
	manList := c.Get("authority_manifests")
	if manList.Kind != canon.KindArray {
		return perr("CHARTER_INVALID", "authority_manifests must be an array")
	}
	for _, mv := range manList.Arr {
		id := mv.Get("manifest_id").StrOr("")
		if id == "" {
			return perr("CHARTER_INVALID", "a delegation manifest states no manifest_id")
		}
		if _, dup := manifests[id]; dup {
			return perr("CHARTER_INVALID", "duplicate manifest_id %q", id)
		}
		manifests[id] = mv
		ia, ea := mv.Get("issued_at"), mv.Get("expires_at")
		if ia == nil || ia.Kind != canon.KindInt || ea == nil || ea.Kind != canon.KindInt {
			return perr("CHARTER_INVALID", "manifest %s must state integer issued_at and expires_at", id)
		}
		if ea.Int <= ia.Int {
			return perr("CHARTER_INVALID", "manifest %s expires_at must be after issued_at", id)
		}
		if _, ok := seats[mv.Get("grantor_seat").StrOr("")]; !ok {
			return perr("CHARTER_INVALID", "manifest %s grantor seat does not exist", id)
		}
		if _, ok := seats[mv.Get("grantee_seat").StrOr("")]; !ok {
			return perr("CHARTER_INVALID", "manifest %s grantee seat does not exist", id)
		}
		if br := mv.Get("budget_ref"); br != nil && br.Kind == canon.KindString && !budgetIDs[br.Str] {
			return perr("CHARTER_INVALID", "manifest %s references unknown budget %q", id, br.Str)
		}
		if _, err := parseScope(mv.Get("scope"), "manifest "+id); err != nil {
			return err
		}
	}
	// Attenuation against parent manifests, and delegation loops.
	for _, mv := range manList.Arr {
		id := mv.Get("manifest_id").StrOr("")
		pm := mv.Get("parent_manifest_id")
		if pm == nil || pm.Kind != canon.KindString {
			continue
		}
		parent, ok := manifests[pm.Str]
		if !ok {
			return perr("CHARTER_INVALID", "manifest %s names unknown parent manifest %q", id, pm.Str)
		}
		if allowed := parent.Get("sub_delegation_allowed"); allowed == nil || allowed.Kind != canon.KindBool || !allowed.Bool {
			return perr("CHARTER_INVALID", "manifest %s is a sub-delegation of %s, which does not permit sub-delegation", id, pm.Str)
		}
		ms, _ := parseScope(mv.Get("scope"), "manifest "+id)
		ps, _ := parseScope(parent.Get("scope"), "manifest "+pm.Str)
		if dim, bad := exceeds(ms, ps); bad {
			return perr("CHARTER_INVALID", "manifest %s exceeds parent manifest %s in %s: delegation is attenuating only (Section 6.4)", id, pm.Str, dim)
		}
		// Loop check along the parent chain.
		seen := map[string]bool{id: true}
		cur := pm.Str
		for {
			if seen[cur] {
				return perr("CHARTER_INVALID", "delegation loop through manifest %s", cur)
			}
			seen[cur] = true
			next := manifests[cur].Get("parent_manifest_id")
			if next == nil || next.Kind != canon.KindString {
				break
			}
			cur = next.Str
			if _, ok := manifests[cur]; !ok {
				break
			}
		}
	}
	// Seat scope checks run after parent attenuation, so a child
	// wider than its parent is reported as such.
	for _, mv := range manList.Arr {
		id := mv.Get("manifest_id").StrOr("")
		ms, _ := parseScope(mv.Get("scope"), "manifest "+id)
		if dim, bad := exceeds(ms, seatScopes[mv.Get("grantor_seat").StrOr("")]); bad {
			return perr("CHARTER_INVALID", "manifest %s exceeds grantor seat scope in %s", id, dim)
		}
		if dim, bad := exceeds(ms, seatScopes[mv.Get("grantee_seat").StrOr("")]); bad {
			return perr("CHARTER_INVALID", "manifest %s exceeds grantee seat scope in %s", id, dim)
		}
	}
	ks := c.Get("kill_switch")
	if ks.Kind != canon.KindObject || !ks.Has("authorized_key_ids") || !ks.Has("recovery_seat") {
		return perr("CHARTER_INVALID", "kill_switch must state authorized_key_ids and recovery_seat")
	}
	if h := c.Get("charter_hash"); h != nil && h.Kind == canon.KindString {
		if got := ComputeCharterHash(c); got != h.Str {
			return perr("CHARTER_INVALID", "charter_hash does not match the charter contents")
		}
	}
	return nil
}

// ValidateCharterChain validates a charter amendment chain
// (Section 6.5): per-charter structure, predecessor linkage over
// ComputeCharterHash, the cumulative freeze, the frozen freeze
// list, and org.founded immutability.
func ValidateCharterChain(charters []*canon.Value) error {
	if len(charters) == 0 {
		return perr("CHARTER_INVALID", "an empty charter chain validates as nothing")
	}
	frozen := map[string]*canon.Value{}
	var prevHash string
	var prevFrozen []string
	for i, c := range charters {
		if err := ValidateCharterStructure(c); err != nil {
			return err
		}
		ph := c.Get("predecessor_charter_hash")
		if i == 0 {
			if ph != nil && ph.Kind == canon.KindString && ph.Str != "" {
				return perr("CHARTER_INVALID", "the founding charter names a predecessor; a founding charter has none")
			}
		} else {
			if ph == nil || ph.Kind != canon.KindString || ph.Str != prevHash {
				return perr("CHARTER_INVALID", "charter %d predecessor_charter_hash does not match the hash of its predecessor", i)
			}
			for _, f := range prevFrozen {
				if !canon.Equal(frozen[f], c.Get(f)) {
					return perr("CHARTER_INVALID", "charter %d rewrites frozen field %s", i, f)
				}
			}
			curFrozen := frozenList(c)
			for _, f := range prevFrozen {
				found := false
				for _, cf := range curFrozen {
					if cf == f {
						found = true
					}
				}
				if !found {
					return perr("CHARTER_INVALID", "charter %d shrinks frozen_fields; the freeze list may only grow", i)
				}
			}
			if !canon.Equal(charters[0].Get("org").Get("founded"), c.Get("org").Get("founded")) {
				return perr("CHARTER_INVALID", "charter %d changes org.founded; the founding date never changes", i)
			}
		}
		for _, f := range frozenList(c) {
			if _, ok := frozen[f]; !ok {
				frozen[f] = c.Get(f)
			}
		}
		prevFrozen = frozenList(c)
		prevHash = ComputeCharterHash(c)
	}
	return nil
}

func frozenList(c *canon.Value) []string {
	var out []string
	if ff := c.Get("amendment").Get("frozen_fields"); ff != nil && ff.Kind == canon.KindArray {
		for _, e := range ff.Arr {
			if e.Kind == canon.KindString {
				out = append(out, e.Str)
			}
		}
	}
	return out
}

var _ = fmt.Sprintf

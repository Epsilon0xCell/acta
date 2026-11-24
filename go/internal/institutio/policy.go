// Standing policy parsing and validation, implementing the
// encodings of specification Section 16.10 decisions 1 to 15 and
// 18 to 24: integer-only, non-negative, non-null, spec-named,
// eagerly and class-locally parsed (decision 24).
//
// Author: Gavin Blacklock
package institutio

import (
	"fmt"
	"sort"

	"acta-go/internal/canon"
)

// Error is a typed Institutio failure with a stable code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func perr(code, format string, args ...interface{}) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Ceilings is one ceiling-curve tier's output (Section 16.3 item 3).
type Ceilings struct {
	MaxBudgetPerAction int64
	MaxBudgetPerEpoch  int64
	MaxIrreversibility int64
	MaxDataSensitivity int64
	MaxDelegationDepth int64
	MaxFanout          int64
}

// Value renders the ceilings as a canonical object value.
func (c Ceilings) Value() *canon.Value {
	return canon.Obj(
		"max_budget_per_action", canon.Int(c.MaxBudgetPerAction),
		"max_budget_per_epoch", canon.Int(c.MaxBudgetPerEpoch),
		"max_data_sensitivity", canon.Int(c.MaxDataSensitivity),
		"max_delegation_depth", canon.Int(c.MaxDelegationDepth),
		"max_fanout", canon.Int(c.MaxFanout),
		"max_irreversibility", canon.Int(c.MaxIrreversibility),
	)
}

// Tier is one ceiling-curve tier.
type Tier struct {
	MinStanding int64
	Ceilings    Ceilings
}

// ClassPolicy is one parsed scope class. Nil pointers mean the
// policy does not state the field; the computation invents no
// default (Section 16.10, repair round 3 position S3).
type ClassPolicy struct {
	MintRate        *int64
	MintCapPerEpoch *int64
	HalfLifeSeconds *int64
	HopPPM          *int64
	BurnUnit        *int64
	BurnMultipliers map[string]int64
	SevereCodes     []string
	CorrelatedPPM   *int64
	Curve           []Tier
	HasCurve        bool
	InheritancePPM  *int64
}

// Diversity holds the parsed policy-level diversity caps.
type Diversity struct {
	PerCounterpartyFractionPPM *int64
	PerTaskTypeFractionPPM     *int64
	PerSubtreeFractionPPM      *int64
	PerCounterpartyAbsolute    *int64
	PerTaskTypeAbsolute        *int64
}

// WitnessPolicy is the decision 15 encoding.
type WitnessPolicy struct {
	KeyIDs []string
	Quorum int64
}

// Policy is a fully parsed standing_policy.
type Policy struct {
	Raw               *canon.Value
	EpochSeconds      *int64
	Classes           map[string]*ClassPolicy
	ClassNames        []string
	Curve             []Tier
	HasCurve          bool
	Diversity         *Diversity
	CountersignReq    map[string]bool
	HasCountersignPol bool
	Witness           *WitnessPolicy
}

func intPtr(n int64) *int64 { return &n }

// strictInt reads an optional integer field under decision 24 rows
// (a) and (b): integers only, non-negative.
func strictInt(obj *canon.Value, field, where string) (*int64, error) {
	v := obj.Get(field)
	if v == nil {
		return nil, nil
	}
	if v.Kind != canon.KindInt {
		return nil, perr("POLICY_INVALID", "%s field %s must be an integer", where, field)
	}
	if v.Int < 0 {
		return nil, perr("POLICY_INVALID", "%s field %s must be non-negative", where, field)
	}
	return intPtr(v.Int), nil
}

// rejectNulls implements decision 24 row (c) over the whole policy.
func rejectNulls(v *canon.Value, path string) error {
	switch v.Kind {
	case canon.KindNull:
		return perr("POLICY_INVALID", "policy field %s is stated as null; absence is expressed by omitting the field", path)
	case canon.KindArray:
		for i, e := range v.Arr {
			if err := rejectNulls(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case canon.KindObject:
		for _, k := range v.Keys {
			if err := rejectNulls(v.Obj[k], path+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseCurve(v *canon.Value, where string) ([]Tier, error) {
	if v.Kind != canon.KindArray {
		return nil, perr("POLICY_INVALID", "%s ceiling_curve must be an array of tiers", where)
	}
	fields := []string{"min_standing", "max_budget_per_action", "max_budget_per_epoch", "max_irreversibility", "max_data_sensitivity", "max_delegation_depth", "max_fanout"}
	var tiers []Tier
	seenMin := map[int64]bool{}
	for i, tv := range v.Arr {
		if tv.Kind != canon.KindObject {
			return nil, perr("POLICY_INVALID", "%s ceiling_curve tier %d is not an object", where, i)
		}
		vals := map[string]int64{}
		for _, f := range fields {
			n, err := strictInt(tv, f, where+" ceiling_curve tier")
			if err != nil {
				return nil, err
			}
			if n == nil {
				return nil, perr("POLICY_INVALID", "%s ceiling_curve tier %d is missing field %s (decision 10 requires all six ceiling fields plus min_standing)", where, i, f)
			}
			vals[f] = *n
		}
		if seenMin[vals["min_standing"]] {
			return nil, perr("POLICY_INVALID", "%s ceiling_curve has two tiers at min_standing %d", where, vals["min_standing"])
		}
		seenMin[vals["min_standing"]] = true
		tiers = append(tiers, Tier{MinStanding: vals["min_standing"], Ceilings: Ceilings{
			MaxBudgetPerAction: vals["max_budget_per_action"], MaxBudgetPerEpoch: vals["max_budget_per_epoch"],
			MaxIrreversibility: vals["max_irreversibility"], MaxDataSensitivity: vals["max_data_sensitivity"],
			MaxDelegationDepth: vals["max_delegation_depth"], MaxFanout: vals["max_fanout"],
		}})
	}
	if len(tiers) == 0 || !seenMin[0] {
		return nil, perr("POLICY_INVALID", "%s ceiling_curve must state an entry tier with min_standing 0", where)
	}
	sort.Slice(tiers, func(a, b int) bool { return tiers[a].MinStanding < tiers[b].MinStanding })
	for i := 1; i < len(tiers); i++ {
		a, b := tiers[i-1].Ceilings, tiers[i].Ceilings
		if b.MaxBudgetPerAction < a.MaxBudgetPerAction || b.MaxBudgetPerEpoch < a.MaxBudgetPerEpoch ||
			b.MaxIrreversibility < a.MaxIrreversibility || b.MaxDataSensitivity < a.MaxDataSensitivity ||
			b.MaxDelegationDepth < a.MaxDelegationDepth || b.MaxFanout < a.MaxFanout {
			return nil, perr("POLICY_INVALID", "%s ceiling_curve tiers must be non-decreasing in every ceiling field", where)
		}
	}
	return tiers, nil
}

func parseClass(name string, v *canon.Value) (*ClassPolicy, error) {
	where := "scope class " + name
	if v.Kind != canon.KindObject {
		return nil, perr("POLICY_INVALID", "%s policy is not an object", where)
	}
	if v.Has("severe_codes") {
		return nil, perr("POLICY_INVALID", "%s states severe_codes; the spec-named field is severe_reason_codes (decision 24 row d)", where)
	}
	if v.Has("diversity_caps") {
		return nil, perr("POLICY_INVALID", "%s states diversity_caps inside a scope class; decision 18 places it at policy level only", where)
	}
	if v.Has("countersign_policy") || v.Has("countersign_required") {
		return nil, perr("POLICY_INVALID", "%s states the countersign requirement inside a scope class; decision 22 fixes it at policy level in one form", where)
	}
	if v.Has("witness_policy") {
		return nil, perr("POLICY_INVALID", "%s states witness_policy inside a scope class; decision 15 places it at policy level only", where)
	}
	cp := &ClassPolicy{BurnMultipliers: map[string]int64{}}
	var err error
	if cp.MintRate, err = strictInt(v, "mint_rate", where); err != nil {
		return nil, err
	}
	if cp.MintCapPerEpoch, err = strictInt(v, "mint_cap_per_epoch", where); err != nil {
		return nil, err
	}
	if cp.BurnUnit, err = strictInt(v, "burn_unit", where); err != nil {
		return nil, err
	}
	if cp.CorrelatedPPM, err = strictInt(v, "correlated_burn_fraction_ppm", where); err != nil {
		return nil, err
	}
	if cp.CorrelatedPPM != nil && *cp.CorrelatedPPM > 1000000 {
		return nil, perr("POLICY_INVALID", "%s correlated_burn_fraction_ppm exceeds 1000000", where)
	}
	if cp.InheritancePPM, err = strictInt(v, "inheritance_factor_ppm", where); err != nil {
		return nil, err
	}
	if cp.InheritancePPM != nil && *cp.InheritancePPM >= 1000000 {
		return nil, perr("POLICY_INVALID", "%s inheritance_factor_ppm must be below 1000000", where)
	}
	// Half-life: canonical name half_life_seconds, documented alias
	// half_life (decision 4). Must be a positive integer.
	hl, err := strictInt(v, "half_life_seconds", where)
	if err != nil {
		return nil, err
	}
	hlAlias, err := strictInt(v, "half_life", where)
	if err != nil {
		return nil, err
	}
	if hl == nil {
		hl = hlAlias
	}
	if hl != nil && *hl <= 0 {
		return nil, perr("POLICY_INVALID", "%s half_life_seconds must be a positive integer", where)
	}
	cp.HalfLifeSeconds = hl
	// Hop attenuation: ppm form, or the bare integer 1 (decision 6).
	hop, err := strictInt(v, "hop_attenuation_ppm", where)
	if err != nil {
		return nil, err
	}
	// Decision 6, as the reference implementations read it: the
	// bare field is consulted only when the ppm field is absent,
	// and then it is conforming only as the integer 1. (A stated
	// bare value beside a stated ppm value is the subject of a
	// recorded differential resolution; see DIFFERENTIAL.md.)
	if bare := v.Get("hop_attenuation"); bare != nil && hop == nil {
		if bare.Kind != canon.KindInt || bare.Int != 1 {
			return nil, perr("POLICY_INVALID", "%s bare hop_attenuation is conforming only as the integer 1 (decision 6)", where)
		}
		hop = intPtr(1000000)
	}
	if hop != nil && (*hop < 1 || *hop > 1000000) {
		return nil, perr("POLICY_INVALID", "%s hop_attenuation_ppm must be in 1..1000000", where)
	}
	cp.HopPPM = hop
	if bm := v.Get("burn_multipliers"); bm != nil {
		if bm.Kind != canon.KindObject {
			return nil, perr("POLICY_INVALID", "%s burn_multipliers must be an object", where)
		}
		for _, code := range bm.Keys {
			n, err := strictInt(bm, code, where+" burn_multipliers")
			if err != nil {
				return nil, err
			}
			cp.BurnMultipliers[code] = *n
		}
	}
	if sc := v.Get("severe_reason_codes"); sc != nil {
		if sc.Kind != canon.KindArray {
			return nil, perr("POLICY_INVALID", "%s severe_reason_codes must be an array of strings", where)
		}
		for _, e := range sc.Arr {
			if e.Kind != canon.KindString {
				return nil, perr("POLICY_INVALID", "%s severe_reason_codes entries must be strings", where)
			}
			cp.SevereCodes = append(cp.SevereCodes, e.Str)
		}
	}
	if cv := v.Get("ceiling_curve"); cv != nil {
		tiers, err := parseCurve(cv, where)
		if err != nil {
			return nil, err
		}
		cp.Curve, cp.HasCurve = tiers, true
	}
	return cp, nil
}

// ParsePolicy parses a standing_policy value completely and
// eagerly (decision 24 row e).
func ParsePolicy(raw *canon.Value) (*Policy, error) {
	if raw == nil || raw.Kind != canon.KindObject {
		return nil, perr("POLICY_INVALID", "standing_policy must be an object")
	}
	if err := rejectNulls(raw, "standing_policy"); err != nil {
		return nil, err
	}
	if raw.Has("severe_codes") || raw.Has("countersign_required") {
		return nil, perr("POLICY_INVALID", "standing_policy states a non-conforming field name (decisions 22 and 24 row d)")
	}
	p := &Policy{Raw: raw, Classes: map[string]*ClassPolicy{}, CountersignReq: map[string]bool{}}
	var err error
	if p.EpochSeconds, err = strictInt(raw, "epoch_seconds", "standing_policy"); err != nil {
		return nil, err
	}
	if p.EpochSeconds != nil && *p.EpochSeconds < 1 {
		return nil, perr("POLICY_INVALID", "standing_policy epoch_seconds must be at least 1 (decision 3)")
	}
	sc := raw.Get("scope_classes")
	if sc == nil {
		return nil, perr("POLICY_INVALID", "standing_policy states no scope_classes")
	}
	if sc.Kind != canon.KindObject {
		return nil, perr("POLICY_INVALID", "scope_classes must be an object mapping class names to class policies (decision 9)")
	}
	for _, name := range sc.Keys {
		cp, err := parseClass(name, sc.Obj[name])
		if err != nil {
			return nil, err
		}
		p.Classes[name] = cp
		p.ClassNames = append(p.ClassNames, name)
	}
	sort.Strings(p.ClassNames)
	if cv := raw.Get("ceiling_curve"); cv != nil {
		tiers, err := parseCurve(cv, "standing_policy")
		if err != nil {
			return nil, err
		}
		p.Curve, p.HasCurve = tiers, true
	}
	if dv := raw.Get("diversity_caps"); dv != nil {
		if dv.Kind != canon.KindObject {
			return nil, perr("POLICY_INVALID", "diversity_caps must be an object")
		}
		d := &Diversity{}
		if d.PerCounterpartyFractionPPM, err = strictInt(dv, "per_counterparty_fraction_ppm", "diversity_caps"); err != nil {
			return nil, err
		}
		if d.PerTaskTypeFractionPPM, err = strictInt(dv, "per_task_type_fraction_ppm", "diversity_caps"); err != nil {
			return nil, err
		}
		if d.PerSubtreeFractionPPM, err = strictInt(dv, "per_subtree_fraction_ppm", "diversity_caps"); err != nil {
			return nil, err
		}
		if d.PerCounterpartyAbsolute, err = strictInt(dv, "per_counterparty_per_epoch", "diversity_caps"); err != nil {
			return nil, err
		}
		if d.PerTaskTypeAbsolute, err = strictInt(dv, "per_task_type_per_epoch", "diversity_caps"); err != nil {
			return nil, err
		}
		for _, f := range []*int64{d.PerCounterpartyFractionPPM, d.PerTaskTypeFractionPPM, d.PerSubtreeFractionPPM} {
			if f != nil && *f > 1000000 {
				return nil, perr("POLICY_INVALID", "diversity_caps fraction exceeds 1000000 ppm")
			}
		}
		if d.PerCounterpartyFractionPPM != nil || d.PerTaskTypeFractionPPM != nil || d.PerSubtreeFractionPPM != nil {
			for _, name := range p.ClassNames {
				if p.Classes[name].MintCapPerEpoch == nil {
					return nil, perr("POLICY_INVALID", "standing_policy states a diversity fraction cap without a mint_cap_per_epoch for scope class %s; the denominator is missing (decision 8)", name)
				}
			}
		}
		p.Diversity = d
	}
	if cpv := raw.Get("countersign_policy"); cpv != nil {
		if cpv.Kind != canon.KindObject {
			return nil, perr("POLICY_INVALID", "countersign_policy must be an object of the form {\"required_for\": [...]} (decision 22)")
		}
		for _, k := range cpv.Keys {
			if k != "required_for" {
				return nil, perr("POLICY_INVALID", "countersign_policy carries key %q; required_for is the only conforming key (decision 22)", k)
			}
		}
		rf := cpv.Get("required_for")
		if rf == nil || rf.Kind != canon.KindArray {
			return nil, perr("POLICY_INVALID", "countersign_policy.required_for must be an array of scope class names (decision 22)")
		}
		for _, e := range rf.Arr {
			if e.Kind != canon.KindString {
				return nil, perr("POLICY_INVALID", "countersign_policy.required_for entries must be strings (decision 22)")
			}
			p.CountersignReq[e.Str] = true
		}
		p.HasCountersignPol = true
	}
	if wp := raw.Get("witness_policy"); wp != nil {
		w, err := ParseWitnessPolicy(wp)
		if err != nil {
			return nil, err
		}
		p.Witness = w
	}
	return p, nil
}

// ParseWitnessPolicy parses the decision 15 witness policy form.
func ParseWitnessPolicy(wp *canon.Value) (*WitnessPolicy, error) {
	if wp.Kind != canon.KindObject {
		return nil, perr("POLICY_INVALID", "witness_policy must be an object {witness_key_ids, quorum} (decision 15)")
	}
	for _, k := range wp.Keys {
		if k != "witness_key_ids" && k != "quorum" {
			return nil, perr("POLICY_INVALID", "witness_policy carries key %q; the only conforming keys are witness_key_ids and quorum (decision 15)", k)
		}
	}
	ids := wp.Get("witness_key_ids")
	if ids == nil || ids.Kind != canon.KindArray {
		return nil, perr("POLICY_INVALID", "witness_policy.witness_key_ids must be an array of strings (decision 15)")
	}
	w := &WitnessPolicy{}
	for _, e := range ids.Arr {
		if e.Kind != canon.KindString {
			return nil, perr("POLICY_INVALID", "witness_policy.witness_key_ids entries must be strings (decision 15)")
		}
		w.KeyIDs = append(w.KeyIDs, e.Str)
	}
	q, err := strictInt(wp, "quorum", "witness_policy")
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, perr("POLICY_INVALID", "witness_policy states no quorum (decision 15)")
	}
	w.Quorum = *q
	if w.Quorum < 1 || w.Quorum > int64(len(w.KeyIDs)) {
		return nil, perr("POLICY_INVALID", "witness_policy quorum %d is outside 1..%d (decision 15)", w.Quorum, len(w.KeyIDs))
	}
	return w, nil
}

// ValidateStandingPolicy is the charter-validation door: full
// parse plus the invariant I5 severe floor (decisions 1 and 2).
func ValidateStandingPolicy(raw *canon.Value) error {
	p, err := ParsePolicy(raw)
	if err != nil {
		return err
	}
	for _, name := range p.ClassNames {
		cp := p.Classes[name]
		for _, code := range cp.SevereCodes {
			if cp.MintCapPerEpoch == nil {
				return perr("POLICY_INVALID", "scope class %s has severe reason code %q but no mint_cap_per_epoch; its epoch of mint is unbounded and the severe floor cannot be checked (invariant I5)", name, code)
			}
			if cp.BurnUnit == nil {
				return perr("POLICY_INVALID", "scope class %s has severe reason code %q but no burn_unit (decision 1)", name, code)
			}
			mult, ok := cp.BurnMultipliers[code]
			if !ok {
				return perr("POLICY_INVALID", "scope class %s states no burn multiplier for severe reason code %q (decision 1)", name, code)
			}
			if *cp.BurnUnit*mult < *cp.MintCapPerEpoch {
				return perr("POLICY_INVALID", "scope class %s severe burn %d is below its epoch mint cap %d (invariant I5)", name, *cp.BurnUnit*mult, *cp.MintCapPerEpoch)
			}
		}
	}
	return nil
}

// CeilingsFor returns the ceilings in force for a Standing value in
// a class: the class curve where stated, the policy curve
// otherwise, an error where neither is stated (decisions 21, 23).
func (p *Policy) CeilingsFor(class string, standing int64) (Ceilings, error) {
	var tiers []Tier
	if cp, ok := p.Classes[class]; ok && cp.HasCurve {
		tiers = cp.Curve
	} else if p.HasCurve {
		tiers = p.Curve
	} else {
		return Ceilings{}, perr("UNSPECIFIED_BY_SPEC", "standing_policy states no ceiling_curve for scope class %s; producing ceilings requires one (decisions 21 and 23)", class)
	}
	out := tiers[0].Ceilings
	for _, t := range tiers {
		if t.MinStanding <= standing {
			out = t.Ceilings
		} else {
			break
		}
	}
	return out, nil
}

// Hash returns the standing policy hash: SHA-256 over the canonical
// encoding of the policy as written.
func (p *Policy) Hash() string {
	return sha256Hex(canon.Encode(p.Raw))
}

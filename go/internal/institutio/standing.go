// ComputeStanding: the normative Standing computation of
// specification Section 16, with the encodings and fixed
// parameters of Section 16.10 decisions 1 to 24. Integer
// arithmetic only; checked arithmetic throughout (decision 14);
// deterministic: the same chain, policy and evaluation time
// produce the same result on any conforming implementation
// (invariant I2).
//
// Author: Gavin Blacklock
package institutio

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"sort"

	"acta-go/internal/acta"
	"acta-go/internal/canon"
)

// CounterpartyPayloadType is the DSSE payload type of the
// countersigned outcome descriptor (decision 16).
const CounterpartyPayloadType = "application/vnd.acta.counterparty-outcome.v0.1+json"

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ClassResult is one scope class entry of a Standing result.
type ClassResult struct {
	Standing      int64
	Ceiling       int64
	Ceilings      Ceilings
	Actions       int64
	Denials       int64
	Minted        int64
	MintedDecayed int64
	Burned        int64
	DecayApplied  int64
	BurnReceipts  int64
	BurnRecorded  int64
	Promotions    int64
	Demotions     int64
	Killed        bool
	DenialsByCode map[string]int64
}

// Value renders the result entry as a canonical object value.
func (r *ClassResult) Value() *canon.Value {
	return canon.Obj(
		"standing", canon.Int(r.Standing),
		"ceiling", canon.Int(r.Ceiling),
		"ceilings", r.Ceilings.Value(),
		"actions", canon.Int(r.Actions),
		"denials", canon.Int(r.Denials),
		"minted", canon.Int(r.Minted),
		"minted_decayed", canon.Int(r.MintedDecayed),
		"burned", canon.Int(r.Burned),
		"decay_applied", canon.Int(r.DecayApplied),
		"burn_receipts", canon.Int(r.BurnReceipts),
		"burn_recorded", canon.Int(r.BurnRecorded),
		"promotions", canon.Int(r.Promotions),
		"demotions", canon.Int(r.Demotions),
		"killed", canon.Bool(r.Killed),
	)
}

// ResultValue renders a whole Standing result.
func ResultValue(res map[string]*ClassResult) *canon.Value {
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	sort.Strings(names)
	out := canon.Obj()
	for _, n := range names {
		out.Set(n, res[n].Value())
	}
	return out
}

type parsedReceipt struct {
	raw          *canon.Value
	typ          string
	agentID      string
	hasAgent     bool
	ts           int64
	class        string
	actionName   string
	argsHash     *string
	resultHash   *string
	riskWeight   *int64
	receiptID    *string
	reasonCode   string
	burnAmount   *int64
	counterparty *string
	subtree      *string
	depth        int64
	counterSig   *string
	killedIDs    []string
}

// strictReceiptInt reads an integer receipt scalar under decision
// 24 rows (a) and (b). It searches the receipt level, then the
// action level.
func strictReceiptInt(r *canon.Value, field string) (*int64, error) {
	for _, holder := range []*canon.Value{r, r.Get("action")} {
		if holder == nil || holder.Kind != canon.KindObject {
			continue
		}
		v := holder.Get(field)
		if v == nil {
			continue
		}
		if v.Kind == canon.KindNull {
			return nil, perr("INVALID_RECEIPT", "receipt field %s is stated as null; absence is expressed by omitting the field (decision 24 row c)", field)
		}
		if v.Kind != canon.KindInt {
			return nil, perr("INVALID_RECEIPT", "receipt field %s must be an integer (decision 24 row a)", field)
		}
		if v.Int < 0 {
			return nil, perr("INVALID_RECEIPT", "receipt field %s must be non-negative (decision 24 row b)", field)
		}
		n := v.Int
		return &n, nil
	}
	return nil, nil
}

// strictReceiptString reads a string receipt field from the
// receipt level, then the action level, with stated nulls rejected
// (decision 24 row c, repair round 6 item W1).
func strictReceiptString(r *canon.Value, field string) (*string, error) {
	for _, holder := range []*canon.Value{r, r.Get("action")} {
		if holder == nil || holder.Kind != canon.KindObject {
			continue
		}
		v := holder.Get(field)
		if v == nil {
			continue
		}
		if v.Kind == canon.KindNull {
			return nil, perr("INVALID_RECEIPT", "receipt field %s is stated as null (decision 24 row c)", field)
		}
		if v.Kind != canon.KindString {
			return nil, perr("INVALID_RECEIPT", "receipt field %s must be a string", field)
		}
		s := v.Str
		return &s, nil
	}
	return nil, nil
}

func parseReceipt(r *canon.Value) (*parsedReceipt, error) {
	if r.Kind != canon.KindObject {
		return nil, perr("INVALID_RECEIPT", "a receipt is not an object")
	}
	pr := &parsedReceipt{raw: r}
	tv := r.Get("receipt_type")
	if tv == nil || tv.Kind != canon.KindString {
		return nil, perr("INVALID_RECEIPT", "a receipt states no receipt_type")
	}
	pr.typ = tv.Str
	if !acta.ReceiptTypes[pr.typ] {
		return nil, perr("INVALID_RECEIPT", "unknown receipt type %q must be rejected, not ignored", pr.typ)
	}
	tsv := r.Get("timestamp")
	if tsv == nil || tsv.Kind != canon.KindInt {
		return nil, perr("INVALID_RECEIPT", "a receipt timestamp must be an integer number of seconds (decision 24 row a)")
	}
	if tsv.Int < 0 {
		return nil, perr("INVALID_RECEIPT", "a receipt timestamp must be non-negative (decision 24 row b)")
	}
	pr.ts = tsv.Int
	if av := r.Get("agent"); av != nil {
		if av.Kind != canon.KindObject {
			return nil, perr("INVALID_RECEIPT", "a stated agent must be the agent object, not a bare value (repair round 6 item W5)")
		}
		pr.hasAgent = true
		if idv := av.Get("id"); idv != nil {
			if idv.Kind != canon.KindString {
				return nil, perr("INVALID_RECEIPT", "agent id must be a string")
			}
			pr.agentID = idv.Str
		}
	}
	if idv := r.Get("receipt_id"); idv != nil {
		if idv.Kind != canon.KindString {
			return nil, perr("INVALID_RECEIPT", "receipt_id must be a string (decision 19)")
		}
		s := idv.Str
		pr.receiptID = &s
	}
	if act := r.Get("action"); act != nil && act.Kind != canon.KindObject {
		return nil, perr("INVALID_RECEIPT", "a stated action must be an object")
	}
	// Scope class: action level, then the receipt extension field,
	// then the default class.
	if s, err := strictReceiptString(r, "scope_class"); err != nil {
		return nil, err
	} else if s != nil {
		pr.class = *s
	}
	if pr.class == "" {
		if s := r.Get("standing_scope_class"); s != nil {
			if s.Kind != canon.KindString {
				return nil, perr("INVALID_RECEIPT", "standing_scope_class must be a string")
			}
			pr.class = s.Str
		}
	}
	if pr.class == "" {
		pr.class = "default"
	}
	if n := r.Get("action"); n != nil {
		if nv := n.Get("name"); nv != nil && nv.Kind == canon.KindString {
			pr.actionName = nv.Str
		}
	}
	var err error
	if pr.riskWeight, err = strictReceiptInt(r, "risk_weight"); err != nil {
		return nil, err
	}
	if pr.burnAmount, err = strictReceiptInt(r, "burn_amount"); err != nil {
		return nil, err
	}
	depth, err := strictReceiptInt(r, "delegation_depth")
	if err != nil {
		return nil, err
	}
	if depth != nil {
		pr.depth = *depth
	}
	if pr.counterparty, err = strictReceiptString(r, "counterparty_id"); err != nil {
		return nil, err
	}
	if pr.subtree, err = strictReceiptString(r, "subtree_root_id"); err != nil {
		return nil, err
	}
	if pr.argsHash, err = strictReceiptString(r, "arguments_hash"); err != nil {
		return nil, err
	}
	if rh := r.Get("result_hash"); rh != nil {
		if rh.Kind == canon.KindNull {
			return nil, perr("INVALID_RECEIPT", "result_hash is stated as null")
		}
		if rh.Kind == canon.KindString {
			s := rh.Str
			pr.resultHash = &s
		}
	}
	if cs, err := strictReceiptString(r, "counterparty_sig"); err != nil {
		return nil, err
	} else {
		pr.counterSig = cs
	}
	if rc := r.Get("reason_code"); rc != nil {
		if rc.Kind != canon.KindString {
			return nil, perr("INVALID_RECEIPT", "reason_code must be a string")
		}
		pr.reasonCode = rc.Str
	}
	if kv := r.Get("killed_agent_ids"); kv != nil {
		if kv.Kind != canon.KindArray {
			return nil, perr("INVALID_RECEIPT", "killed_agent_ids must be an array of strings (decision 17)")
		}
		for _, e := range kv.Arr {
			if e.Kind != canon.KindString {
				return nil, perr("INVALID_RECEIPT", "killed_agent_ids entries must be strings (decision 17)")
			}
			pr.killedIDs = append(pr.killedIDs, e.Str)
		}
	}
	return pr, nil
}

func mulChecked(a, b int64) (int64, error) {
	z := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	if !z.IsInt64() {
		return 0, perr("OVERFLOW", "Standing arithmetic overflowed; an overflow is an error, never a wrap (decision 14)")
	}
	return z.Int64(), nil
}

// attenuate computes floor(q * ppm^depth / 1000000^depth) exactly.
func attenuate(q, ppm, depth int64) (int64, error) {
	num := big.NewInt(q)
	den := big.NewInt(1)
	p := big.NewInt(ppm)
	m := big.NewInt(1000000)
	for i := int64(0); i < depth; i++ {
		num.Mul(num, p)
		den.Mul(den, m)
	}
	z := new(big.Int).Quo(num, den)
	if !z.IsInt64() {
		return 0, perr("OVERFLOW", "Standing arithmetic overflowed (decision 14)")
	}
	return z.Int64(), nil
}

// outcomeDescriptor builds the decision 16 descriptor bytes.
func outcomeDescriptor(pr *parsedReceipt) []byte {
	nullOrStr := func(s *string) *canon.Value {
		if s == nil {
			return canon.Null
		}
		return canon.Str(*s)
	}
	var rw *canon.Value = canon.Null
	if pr.riskWeight != nil {
		rw = canon.Int(*pr.riskWeight)
	}
	obj := canon.Obj(
		"agent_id", canon.Str(pr.agentID),
		"action_name", canon.Str(pr.actionName),
		"arguments_hash", nullOrStr(pr.argsHash),
		"receipt_id", nullOrStr(pr.receiptID),
		"result_hash", nullOrStr(pr.resultHash),
		"risk_weight", rw,
		"scope_class", canon.Str(pr.class),
		"timestamp", canon.Int(pr.ts),
	)
	return canon.Encode(obj)
}

type mintEvent struct {
	amount int64
	ts     int64
}

type classState struct {
	res        *ClassResult
	mintEvents []mintEvent
	denialOrd  int64
}

type usageKey struct {
	class string
	epoch int64
	dim   string
	key   string
}

// ComputeStanding runs the Section 16 computation for one agent.
// When agentID is empty, receipts of every agent are computed as
// one segment per agent and the result is the per-agent map
// flattened by the caller; the fixture and checkpoint paths always
// name an agent. counterpartyKeys maps counterparty identifiers to
// pinned Ed25519 public keys for countersignature verification.
func ComputeStanding(receipts *canon.Value, policyRaw *canon.Value, evalTime *int64, agentID string, counterpartyKeys map[string]ed25519.PublicKey) (map[string]*ClassResult, error) {
	pol, err := ParsePolicy(policyRaw)
	if err != nil {
		return nil, err
	}
	if receipts == nil || receipts.Kind != canon.KindArray {
		return nil, perr("INVALID_RECEIPT", "the receipt segment must be an array")
	}
	parsed := make([]*parsedReceipt, 0, len(receipts.Arr))
	seenIDs := map[string]bool{}
	var maxTS int64
	for _, rv := range receipts.Arr {
		pr, err := parseReceipt(rv)
		if err != nil {
			return nil, err
		}
		if pr.receiptID != nil {
			if seenIDs[*pr.receiptID] {
				return nil, perr("DUPLICATE_RECEIPT_ID", "receipt_id %q appears twice in one segment (decision 19)", *pr.receiptID)
			}
			seenIDs[*pr.receiptID] = true
		}
		if pr.ts > maxTS {
			maxTS = pr.ts
		}
		parsed = append(parsed, pr)
	}
	eval := maxTS
	if evalTime != nil {
		if *evalTime < 0 {
			return nil, perr("INVALID_RECEIPT", "eval_time must be a non-negative integer number of seconds (decision 24)")
		}
		eval = *evalTime
	}
	// Classes each agent touches anywhere in the segment, for the
	// correlated burn of decision 7 (including classes first
	// touched after the denial).
	touched := map[string]map[string]bool{}
	for _, pr := range parsed {
		if touched[pr.agentID] == nil {
			touched[pr.agentID] = map[string]bool{}
		}
		touched[pr.agentID][pr.class] = true
	}
	states := map[string]*classState{}
	getState := func(class string) *classState {
		st, ok := states[class]
		if !ok {
			st = &classState{res: &ClassResult{DenialsByCode: map[string]int64{}}}
			states[class] = st
		}
		return st
	}
	usage := map[usageKey]int64{}
	killed := map[string]bool{}
	epochOf := func(ts int64) int64 {
		if pol.EpochSeconds == nil {
			return 0
		}
		return ts / *pol.EpochSeconds
	}
	for _, pr := range parsed {
		if pr.typ == "KILL-BURN" {
			killed[pr.agentID] = true
			for _, id := range pr.killedIDs {
				killed[id] = true
			}
		}
		if agentID != "" && pr.agentID != agentID {
			continue
		}
		switch pr.typ {
		case "ACTION":
			st := getState(pr.class)
			st.res.Actions++
			if killed[pr.agentID] {
				continue // a kill is absorbing: post-kill actions mint nothing (Section 16.6)
			}
			cp := pol.Classes[pr.class]
			if cp == nil || cp.MintRate == nil {
				return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy does not state mint_rate for scope class %s; the computation invents no default", pr.class)
			}
			rw := int64(1)
			if pr.riskWeight != nil {
				rw = *pr.riskWeight
			}
			amount, err := mulChecked(*cp.MintRate, rw)
			if err != nil {
				return nil, err
			}
			if pr.depth > 0 {
				if cp.HopPPM == nil {
					return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy does not state hop_attenuation_ppm for scope class %s; a mint at delegation depth %d cannot be attenuated", pr.class, pr.depth)
				}
				amount, err = attenuate(amount, *cp.HopPPM, pr.depth)
				if err != nil {
					return nil, err
				}
			}
			if pol.CountersignReq[pr.class] {
				ok := false
				if pr.counterSig != nil && pr.counterparty != nil {
					if key, has := counterpartyKeys[*pr.counterparty]; has {
						sig, derr := base64.StdEncoding.DecodeString(*pr.counterSig)
						if derr == nil && len(key) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize {
							ok = ed25519.Verify(key, acta.PAE(CounterpartyPayloadType, outcomeDescriptor(pr)), sig)
						}
					}
				}
				if !ok {
					amount = 0 // uncountersigned where required mints zero (invariant I4, decision 11)
				}
			}
			epoch := epochOf(pr.ts)
			credited := amount
			if cp.MintCapPerEpoch != nil {
				rem := *cp.MintCapPerEpoch - usage[usageKey{pr.class, epoch, "epoch", ""}]
				if rem < credited {
					credited = rem
				}
			}
			if pol.Diversity != nil && credited > 0 {
				type dimCap struct {
					dim string
					key string
					cap *int64
				}
				var dims []dimCap
				cpKey := ""
				if pr.counterparty != nil {
					cpKey = *pr.counterparty
				}
				subKey := pr.agentID
				if pr.subtree != nil {
					subKey = *pr.subtree
				}
				fracCap := func(frac *int64) *int64 {
					if frac == nil {
						return nil
					}
					c := *cp.MintCapPerEpoch * *frac / 1000000
					return &c
				}
				minCap := func(a, b *int64) *int64 {
					if a == nil {
						return b
					}
					if b == nil {
						return a
					}
					if *b < *a {
						return b
					}
					return a
				}
				d := pol.Diversity
				dims = append(dims,
					dimCap{"counterparty", cpKey, minCap(fracCap(d.PerCounterpartyFractionPPM), d.PerCounterpartyAbsolute)},
					dimCap{"task", pr.actionName, minCap(fracCap(d.PerTaskTypeFractionPPM), d.PerTaskTypeAbsolute)},
					dimCap{"subtree", subKey, fracCap(d.PerSubtreeFractionPPM)},
				)
				for _, dc := range dims {
					if dc.cap == nil {
						continue
					}
					rem := *dc.cap - usage[usageKey{pr.class, epoch, dc.dim, dc.key}]
					if rem < credited {
						credited = rem
					}
				}
				if credited > 0 {
					for _, dc := range dims {
						if dc.cap == nil {
							continue
						}
						usage[usageKey{pr.class, epoch, dc.dim, dc.key}] += credited
					}
				}
			}
			if credited < 0 {
				credited = 0
			}
			if cp.MintCapPerEpoch != nil {
				usage[usageKey{pr.class, epoch, "epoch", ""}] += credited
			}
			st.res.Minted += credited
			if credited > 0 {
				st.mintEvents = append(st.mintEvents, mintEvent{amount: credited, ts: pr.ts})
			}
		case "DENIAL":
			st := getState(pr.class)
			st.res.Denials++
			st.denialOrd++
			if pr.reasonCode != "" {
				st.res.DenialsByCode[pr.reasonCode]++
			}
			cp := pol.Classes[pr.class]
			if cp == nil || cp.BurnUnit == nil {
				return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy does not state burn_unit for scope class %s; a denial cannot burn an invented value (decision 1)", pr.class)
			}
			mult, ok := cp.BurnMultipliers[pr.reasonCode]
			if !ok {
				return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy states no burn multiplier for reason code %q in scope class %s (decision 1)", pr.reasonCode, pr.class)
			}
			burn, err := mulChecked(*cp.BurnUnit, mult)
			if err != nil {
				return nil, err
			}
			burn, err = mulChecked(burn, st.denialOrd*st.denialOrd)
			if err != nil {
				return nil, err
			}
			st.res.Burned += burn
			severe := false
			for _, c := range cp.SevereCodes {
				if c == pr.reasonCode {
					severe = true
				}
			}
			if severe {
				others := []string{}
				for cls := range touched[pr.agentID] {
					if cls != pr.class {
						others = append(others, cls)
					}
				}
				if len(others) > 0 {
					if cp.CorrelatedPPM == nil {
						return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy does not state correlated_burn_fraction_ppm for scope class %s; a severe denial cannot burn correlated classes by an invented fraction (decision 7)", pr.class)
					}
					corr := burn * *cp.CorrelatedPPM / 1000000
					sort.Strings(others)
					for _, cls := range others {
						getState(cls).res.Burned += corr
					}
				}
			}
		case "BURN":
			st := getState(pr.class)
			st.res.BurnReceipts++
			if pr.burnAmount != nil {
				st.res.BurnRecorded += *pr.burnAmount
			}
		case "PROMOTION":
			getState(pr.class).res.Promotions++
		case "DEMOTION":
			getState(pr.class).res.Demotions++
		case "KILL-BURN":
			getState(pr.class)
		case "GRANT", "REVOCATION":
			// Inert for Standing: tallied nowhere, confer nothing.
		}
	}
	out := map[string]*ClassResult{}
	for class, st := range states {
		res := st.res
		if len(st.mintEvents) > 0 {
			cp := pol.Classes[class]
			if cp == nil || cp.HalfLifeSeconds == nil {
				return nil, perr("UNSPECIFIED_BY_SPEC", "standing_policy does not state half_life_seconds for scope class %s; mint cannot decay by an invented half-life (decision 4)", class)
			}
			hl := *cp.HalfLifeSeconds
			var decayed int64
			for _, ev := range st.mintEvents {
				age := eval - ev.ts
				if age < 0 {
					age = 0
				}
				halvings := age / hl
				if halvings >= 63 {
					continue
				}
				decayed += ev.amount >> uint(halvings)
			}
			res.MintedDecayed = decayed
		}
		if agentID != "" && killed[agentID] {
			// A kill burns the seat to zero in every class
			// (Section 16.6): no decayed mint survives it, and
			// the whole minted total is reported as removed.
			res.MintedDecayed = 0
		}
		res.DecayApplied = res.Minted - res.MintedDecayed
		standing := res.MintedDecayed - res.Burned
		if standing < 0 {
			standing = 0
		}
		res.Killed = killed[agentID] || (agentID == "" && false)
		if agentID != "" && killed[agentID] {
			standing = 0
		}
		res.Standing = standing
		ceil, err := pol.CeilingsFor(class, standing)
		if err != nil {
			return nil, err
		}
		res.Ceilings = ceil
		res.Ceiling = ceil.MaxBudgetPerAction
		out[class] = res
	}
	return out, nil
}

// EffectiveAuthority returns the Section 16.1 minimum of grant,
// manifest and Standing ceilings, per ceiling field.
func EffectiveAuthority(grant, manifest, standing Ceilings) Ceilings {
	min3 := func(a, b, c int64) int64 {
		m := a
		if b < m {
			m = b
		}
		if c < m {
			m = c
		}
		return m
	}
	return Ceilings{
		MaxBudgetPerAction: min3(grant.MaxBudgetPerAction, manifest.MaxBudgetPerAction, standing.MaxBudgetPerAction),
		MaxBudgetPerEpoch:  min3(grant.MaxBudgetPerEpoch, manifest.MaxBudgetPerEpoch, standing.MaxBudgetPerEpoch),
		MaxIrreversibility: min3(grant.MaxIrreversibility, manifest.MaxIrreversibility, standing.MaxIrreversibility),
		MaxDataSensitivity: min3(grant.MaxDataSensitivity, manifest.MaxDataSensitivity, standing.MaxDataSensitivity),
		MaxDelegationDepth: min3(grant.MaxDelegationDepth, manifest.MaxDelegationDepth, standing.MaxDelegationDepth),
		MaxFanout:          min3(grant.MaxFanout, manifest.MaxFanout, standing.MaxFanout),
	}
}

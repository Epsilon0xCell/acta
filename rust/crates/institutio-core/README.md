# institutio-core

Author: Gavin Blacklock

The Institutio layer of the programme in Rust: the charter
(`institutio.json`) model and validator, ComputeStanding, and
Standing checkpoints, implementing specification Sections 6, 7
(the Standing ground of the Provable Kill), and 16 of
`../../SPEC-v0.1-and-90-day-plan.md`, including the Section 16.10
encoding amendment of 2026-11-23.

Dependency rule: this crate depends on acta-core only. acta-core
never depends on it. The verifier and conformance runner in
acta-verify sit above both.

## What is implemented

- **Charter** (`charter.rs`): validation mirroring the Python
  prototype check for check (required fields, now including
  `standing_policy`, `anchoring`, and `org.founded`; seats,
  budgets, succession, kill switch), dimension-by-dimension
  attenuation (a child delegation wider than its parent manifest,
  its grantor seat, or its grantee seat in any of tools, resources,
  operations, or limits fails, including a parent limit the child
  leaves uncapped; unknown scope dimensions are rejected),
  delegation loop detection through both the parent manifest chain
  and the seat graph, expiry ordering, and the charter hash chain
  for amendments (founding charter has no predecessor; every
  amendment names the previous charter hash). Charters hash over
  canonical JSON and sign through a DSSE-style envelope with
  Ed25519, using acta-core's signing code. Authentication
  (re-audit finding N1): `validate_charter` and `verify_charter`
  verify the envelope signature against a pinned `TrustSet` and a
  caller-supplied authorised key set, never against the key
  carried inside the envelope; chains anchor on a caller-pinned
  founder set, amendments verify against the verified
  predecessor's authorised set with no fallback when it is empty,
  and the freeze is cumulative, with the freeze list itself
  frozen and `org.founded` immutable. The unauthenticated
  structural check is exported as `validate_charter_structure`,
  named for what it is.
- **ComputeStanding** (`standing.rs`): the one definition in this
  workspace, written from the specification text of Section 16 as
  amended by Section 16.10. Per scope class; pure and
  deterministic; integer arithmetic only. Mint only from
  countersigned-where-required, incident-free ACTION receipts, at
  `mint_rate` per unit of `risk_weight`, hop-attenuated, clipped
  by the per-epoch mint cap and the diversity caps (absolute and
  fraction-of-mint-cap forms, including the subtree cap keyed by
  `subtree_root_id`) before it counts. Countersigning is
  cryptographic (finding N4): the computation receives pinned
  counterparty keys and verifies the signature over the bound
  outcome descriptor (receipt id, arguments hash, result hash,
  risk weight); presence alone mints zero. Burn super-linear in
  the denial ordinal (`burn_unit * multiplier * n * n`), with a
  policy fraction of a severe burn applied across every other
  class the agent has a receipt in anywhere in the segment
  (decision 7). Decay exponential at the class half-life, applied
  per mint event in whole half-lives; a zero half-life is a
  policy error, never a divide by zero (finding N3). Burns do not
  decay. KILL-BURN zeroes the agent and its named subtree; later
  actions mint nothing. Effective authority is the minimum of
  charter grant, delegation manifest, and Standing ceiling.
- **StandingCheckpoint** (`checkpoint.rs`): the Section 16.3
  object, including the `eval_time` field added by Section 16.10,
  decision 5, built by recomputation over a signed chain segment,
  signed by its operator, cosigned by k-of-n witnesses, and
  verified the stranger's way (Section 16.7): recompute and
  compare, verify signatures, count the quorum. Verification
  rejects (finding M8): recomputation mismatch, an operator
  signature failing under the pinned key for its claimed id, and
  an unmet quorum are errors, not verdict fields. An unwitnessed
  checkpoint is labelled internal-only (invariant I8).
- **The Provable Kill** (`tests/provable_kill.rs`): the full
  Section 7 scenario against the Rust crates. A rogue seat earns
  Standing 80 over a simulated 7 days, is revoked, and is
  kill-burned to zero in every class; its direct, child-delegation,
  and replay attempts are each denied `revoked` with
  `standing-ceiling` recorded as an independent second ground; the
  sibling's checkpoint recomputes unchanged and the sibling acts
  again after the kill.

## Specification gaps found in Section 16, now closed

Building this crate against the specification text, rather than
against the Python prototype's defaults, produced a list of
fifteen places where Section 16 was silent. On 2026-11-23 the
specification was amended: the new Section 16.10,
"Encodings and fixed parameters", decides every item below, in
the same numbering, and this crate implements the decisions.
What still raises the typed error
`InstitutioError::UnspecifiedBySpec` is a policy that omits a
value Section 16.10 requires the policy itself to state, and the
one item the amendment deliberately reserves (gap 13).

1. **The burn base.** Closed by Section 16.10, decision 1:
   `burn_unit`, a per-scope-class policy field in Standing units,
   is what `burn_multipliers` multiply. A policy that omits it
   stops the computation with `UnspecifiedBySpec`, as before, now
   because the amended text requires the field, not because the
   text is silent.
2. **The super-linear burn form.** Closed by Section 16.10,
   decision 2: the closed form is `burn_unit * multiplier * n^2`
   for the n-th denial in a class (the blueprint's rule D4 form),
   and the invariant I5 severe floor is both a policy-validation
   condition (`burn_unit * multiplier >= mint_cap_per_epoch` for
   severe codes, enforced in `validate_policy`) and a consequence
   of the closed form for valid policies. No computation-time
   maximum is applied.
3. **The epoch.** Closed by Section 16.10, decision 3: the policy
   field is `epoch_seconds` (at least 1 when present), the epoch
   of a timestamp is its Euclidean quotient by `epoch_seconds`,
   and an absent field means a single epoch numbered 0.
4. **The half-life encoding.** Closed by Section 16.10,
   decision 4: the field is `half_life_seconds`, a positive
   integer of seconds (the bare `half_life` name remains a
   deprecated alias read as seconds), and decay is discretised in
   whole half-lives per mint event
   (`amount >> (age / half_life_seconds)`).
5. **The evaluation time.** Closed by Section 16.10, decision 5:
   the signature is `ComputeStanding(chain, standing_policy,
   eval_time)`, `eval_time` is integer seconds defaulting to the
   segment's latest timestamp, and the checkpoint object in
   Section 16.3 now carries `eval_time` as a normative field.
6. **The hop attenuation encoding and target.** Closed by
   Section 16.10, decision 6: the field is `hop_attenuation_ppm`
   (1 to 1,000,000), and the factor scales both mint and ceilings.
   A bare `hop_attenuation` is conforming only as the integer 1.
7. **The correlated burn fraction.** Closed by Section 16.10,
   decision 7: the field is `correlated_burn_fraction_ppm`, and
   the correlated classes of a class for an agent are every other
   class in which that agent has at least one receipt in the
   segment.
8. **The diversity cap encoding.** Closed by Section 16.10,
   decision 8: the fraction forms
   (`per_counterparty_fraction_ppm`, `per_task_type_fraction_ppm`,
   `per_subtree_fraction_ppm`) are fractions of the class
   `mint_cap_per_epoch` for the epoch; the absolute per-epoch
   forms remain conforming, and the smaller binds where both are
   stated. The subtree cap, which had no field at all, is keyed by
   the receipt's `subtree_root_id` extension field (Section 16.3,
   receipt extension 6, added by the amendment).
9. **The scope_classes encoding.** Closed by Section 16.10,
   decision 9: the map form, class name to class policy object, is
   the only conforming form.
10. **The ceiling curve encoding.** Closed by Section 16.10,
    decision 10: an array of tier objects (`min_standing` plus the
    six ceiling fields), no two tiers sharing a `min_standing`, an
    entry tier at `min_standing` 0, every ceiling field
    non-decreasing in `min_standing`; the tier in force is the
    greatest tier not exceeding the Standing value. The two new
    structural rules are enforced in `validate_policy`.
11. **The countersign weight.** Closed by Section 16.10,
    decision 11: where the `countersign_policy` does not require
    a countersignature for a class, an uncountersigned completed
    action mints at full weight; where it does require one, it
    mints zero. There is no reduced-weight tier in v0.1.
12. **Whether burns decay.** Closed by Section 16.10,
    decision 12, in one sentence: burns do not decay; decay
    applies to mint events only.
13. **The inheritance factor's event.** Closed by Section 16.10,
    decision 13, by reservation: inheritance is out of v0.1
    scope. The field `inheritance_factor_ppm` (at least 0, below
    1,000,000, range-checked in `validate_policy`) is parsed,
    carried, and hash-committed with the policy, and consumed by
    no v0.1 computation; no v0.1 receipt or charter event carries
    an inheritance, and a v0.1 charter fork starts at zero, which
    satisfies invariant I3's "at most" bound.
14. **The Standing scale.** Closed by Section 16.10, decision 14,
    as a decision: Standing is an unbounded non-negative integer
    under checked arithmetic; overflow is an error, never a wrap.
    The blueprint's proposed 0 to 1,000,000 parts-per-million
    scale (rule D3) was considered and not adopted.
15. **Witness policy encoding.** Closed by Section 16.10,
    decision 15: `witness_policy` is the object
    `{witness_key_ids, quorum}`, with
    1 <= quorum <= the number of listed witness key identifiers.

## Conformance status of the Standing fixtures

Fixtures 11 and 14 of the Python prototype corpus run against
this crate through the conformance runner in acta-verify, each
tried first with its policy exactly as written (spec conformance)
and then with its parameters expressed as an explicit policy
(prototype-parameter conformance). The labels are not merged.
Corpus result at the Section 16.10 amendment: 16 run, 16 passed,
0 failed, 0 skipped.

- **Fixture 14** (decay across an epoch boundary) passes as
  **spec conformance**: mint 24, decay 18, Standing 6, reproduced
  from the fixture's policy exactly as written. The caveat
  formerly attached to this result is withdrawn: the half-life
  field name, unit, and whole-half-life discretisation it relies
  on are now fixed by Section 16.10, decision 4.
- **Fixture 11** (burn to zero) passed as **prototype-parameter
  conformance only** at the time of the Section 16.10 amendment:
  its policy then stated only `mint_rate` and
  `mint_cap_per_epoch`, and the specification attempt stopped
  with `UNSPECIFIED_BY_SPEC: burn_unit`. Repair round 3
  (2026-11-23, finding S3) completed the fixture's policy in the
  corpus itself, and the one remaining specification stop, the
  correlated burn fraction, is now required exactly when another
  class exists in the segment for it to burn (decision 7), as
  the Python computation already had it. Fixture 11 now passes
  as **spec conformance** in both runners, with the same
  expected values (minted 36, burned 36, burn recorded 36,
  Standing 0).

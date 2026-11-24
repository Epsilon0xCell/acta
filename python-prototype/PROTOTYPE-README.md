# Acta, ToolGate, Institutio: v0.1 foundation code

Author: Gavin Blacklock
Licence: Apache License 2.0
Status: foundation build plus the Provable Kill demonstration and
the normative Standing computation (specification Sections 7 and
16), weeks 1 to 4 scope of the combined specification (see
../SPEC-v0.1-and-90-day-plan.md)

## What this is

The first working code for the three-layer programme:

- Acta is the receipt. Every agent action leaves a signed,
  hash-chained, replayable receipt: no receipt, no trust.
- ToolGate is the gate. It pins what an agent's tools are and enforces
  what they may do, before the model ever sees them. Not built yet;
  see below.
- Institutio is the charter. It constitutes an agent organisation: a
  signed charter, delegated-authority manifests that only attenuate,
  budgets, and succession, with a replayable Acta receipt for every
  consequential action.

This foundation implements the pieces every later layer depends on:

- `acta/` : the receipt core. Receipts carry the specification fields
  (delegator, agent and model and version, scope granted, action and
  arguments hash, result hash, effects and sub-delegations, timestamp,
  prior-receipt hash), hash chaining, DSSE-style typed-envelope
  signing, the GRANT, ACTION and DENIAL receipt types plus the
  Standing derived types (BURN, PROMOTION, DEMOTION, KILL-BURN) and
  REVOCATION, and chain verification that detects tampering,
  reordering, and (against an expected head or length) truncation.
  A DENIAL receipt must carry a reason code from the v0.1 set
  (`revoked`, `scope`, `manifest-mismatch`, `budget`,
  `standing-ceiling`); a DENIAL without a valid reason code fails
  validation on construction and on verification.
- `institutio/` : the charter loader and validator for
  `institutio.json` (seats and roles, budgets, amendment and
  succession rules, kill switch), attenuation checking in every
  dimension (a child delegation wider than its parent, its grantor,
  or its grantee fails validation), delegation loop detection, the
  charter hash chain for amendments, and the normative
  ComputeStanding of specification Section 16 (see below). Charter
  validation verifies the charter's DSSE signature, and its trust
  anchor comes from the caller, never from the charter itself
  (re-audit finding C2): the founding charter verifies against a
  pinned founder key set the caller supplies, and each amendment
  verifies against the authorised set of its verified predecessor,
  where an empty predecessor set authorises no amendment at all.
  The freeze is cumulative: an amendment must not rewrite any field
  any predecessor froze, the `frozen_fields` list itself may only
  grow, and `org.founded` never changes. `standing_policy` and
  `anchoring` are required charter fields, and the standing policy
  is itself validated against the burn asymmetry of invariant I5.
  Callers pass a `verifiers` map of key id to Signer; validation
  fails closed without one, and with no pinned key set supplied it
  reports that no anchor exists rather than trusting the document.
- `toolgate/` : the gate prototype, in-process only. It pins tool
  definitions by hash, decides ALLOW or DENY for a proposed call in
  the order of specification Section 16.5 (manifest pin, delegation
  scope covering tool, resource, operation, and the delegation's
  validity window, revocation and replay read from the receipt
  chain itself, budget covering both cumulative spend and the
  delegation's external_calls limit, Standing ceiling covering
  budget per action, budget per epoch, irreversibility, data
  sensitivity, and for sub-delegated calls depth and fanout checked
  against the granting seat's own ceilings), and emits the Acta
  receipts for every decision: ACTION on allow, reason-coded
  DENIAL plus a BURN receipt on deny. The scope recorded on each
  receipt carries every dimension of the granted scope, limits
  included, byte-identical to the scope enforced. Revocation and
  the kill burn are authorized-key acts. A countersignature is
  recorded on a receipt only when a verifier is configured for the
  counterparty and the signature verifies over the bound outcome
  descriptor. Delegation manifests may carry a signature
  (`sign_delegation`); a gate built with `delegation_verifiers`
  verifies carried signatures, and with
  `require_signed_delegations=True` refuses unsigned manifests.
  Stated limitation: without those options the gate trusts its
  in-process caller for manifest contents, because manifests
  arrive as dicts, not as signed wire objects. `acta.verify_chain`
  likewise fails closed: it requires a verifier object and returns
  VERIFIER_REQUIRED without one, binds the envelope key id to the
  verifier's own key id, and rejects an empty chain, so no caller
  can mistake an unverified or empty chain for a verified one.
- `demo_provable_kill.py` : the Provable Kill of specification
  Section 7 as an executable narrative (see below).
- `verifier/verify.py` : the one-file offline verifier. One
  self-contained Python file, standard library only, no imports from
  the packages above. It verifies a bundle's chain, envelope
  signatures, and every DENIAL's reason code, and prints a plain
  verdict that locates the first failure precisely.
- `fixtures/` : thirty-four attack and conformance fixtures as
  data files, each stating its expected verdict, plus a runner
  and a deterministic generator.
- `tests/` : the unittest suite covering all of the above.

## Placeholder signature caveat

Signing uses HMAC-SHA256 behind a signer interface. This is a
deliberate v0.1 placeholder: the Python standard library ships no
asymmetric signature algorithm, and this foundation is standard
library only. The envelope construction is the real one (DSSE-style,
Pre-Auth-Encoding over the payload type and the exact payload bytes;
verifiers check bytes as received and never re-serialise). Real
asymmetric signing (Ed25519, per the specification key identity
model) is a later swap behind the `Signer` interface in
`acta/signing.py`; no caller depends on HMAC directly.

## How to run the tests

Python 3, standard library only. Nothing to install.

```sh
cd code
python3 run_tests.py
```

That runs the unittest suite and the fixture runner and prints an
overall verdict. The suite alone:

```sh
python3 -m unittest discover -s tests -t .
```

## How to run the verifier

```sh
cd code
python3 fixtures/generate_fixtures.py   # only if fixtures are stale
python3 verifier/verify.py fixtures/fixture_01_valid_chain.json \
    --secret-file fixtures/test_secret.txt --key-id acta-test-key-1
```

Expected output: a line starting `PASS: chain verified`. Point it at
`fixture_02_tampered_receipt.json` and it prints a `FAIL` line naming
receipt index 1 and the TAMPERED code, with exit code 1. The fixture
secret is a published test secret, not a real key. Truncation
detection takes `--expected-head HEX` or `--expected-length N`,
supplied from an anchored ledger head.

## How to run the fixtures

```sh
python3 fixtures/run_fixtures.py
python3 fixtures/generate_fixtures.py   # regenerate deterministically
```

Thirty-four fixtures: the original sixteen (a valid chain; a
tampered receipt; a reordered chain; a denial without a reason
code; a child delegation exceeding its parent; a replayed
authorisation attempt recorded as a denial; a truncated chain
checked against an expected head; a forked chain; an unknown
receipt type; a denial with an unknown reason code; burn-to-zero
after one severe denial; a kill attempted by the wrong key; a
non-canonical envelope payload; Standing decay across an epoch
boundary; a manifest-mismatch denial; and a standing-ceiling
denial), plus the Phase 1 expansion, fixtures 17 to 34: an
expired delegation; a tool-not-in-manifest denial; a wrong
payload type envelope; a truncated envelope payload; a replayed
receipt with a duplicate id; a chain missing its middle receipt;
Standing mint-cap saturation; a missing countersignature minting
nothing; witness checkpoints below and at quorum; a checkpoint
bound to another chain's head; a split-view fork against the
expected head; a valid charter succession chain; a charter
amendment with a broken predecessor link; a kill-switch halt
followed by a denied attempt; and the Provable Kill fixtures K1
to K3 (K4 is fixture 12). The full blueprint mapping, its
analogues, and its uncovered remainder are in
`../CORPUS-INDEX.md`. Standing fixtures are recomputed by the
runner and compared against the stated expectation; checkpoint
and charter-chain fixtures use the runner kinds of the same
names.

## Standing: the normative computation and its prototype choices

`institutio/standing.py` implements specification Section 16 as
amended by Section 16.10: Standing per scope class as a pure
function of (receipt chain, standing_policy, evaluation time),
integer arithmetic only. Mint comes only from ACTION receipts,
scaled by risk weight, attenuated per delegation hop by
`hop_attenuation_ppm`, clipped by the per-epoch mint cap and the
per-epoch diversity caps (per counterparty, per task type, per
subtree; absolute forms and fraction-of-mint-cap forms, the
smaller binding). Where the policy requires a counterparty
countersignature, mint is full weight only when the signature
actually verifies, under the signer interface, against the named
counterparty's key over the bound outcome descriptor, which names
the receipt id, the arguments and result hashes, and the risk
weight, so a countersignature cannot be replayed onto another
receipt or re-weighted (re-audit finding M2); a garbage or missing
countersignature mints zero, and the demo's and gate's
countersignatures are real signatures over that descriptor.
DENIAL receipts burn by the Section 16.10 closed form, burn unit
times reason-code multiplier times the square of the denial's
ordinal in its class; the invariant I5 severe floor is a
policy-validation condition (a policy whose severe burn cannot
erase its epoch mint cap is rejected, and an uncapped class is
rejected because its epoch of mint is unbounded), never a
computation-time adjustment. A severe denial also burns
`correlated_burn_fraction_ppm` of its amount in every other class
in which the agent has a receipt in the segment, including a
class first touched after the denial (decision 7). Mint decays by
whole half-lives, per decision 4; future-dated mint events decay
by zero half-lives under that same formula, and the specification
fixes no timestamp monotonicity rule, so none is invented.
BURN, PROMOTION and DEMOTION receipts are tallied and confer
nothing; a KILL-BURN receipt zeroes the killed agent and its
delegation subtree in every class, and never touches an unrelated
seat, in per-agent and firm-wide computations alike.
`build_checkpoint` produces the Section 16.3 StandingCheckpoint,
optionally with witness cosignatures and an issuer signature;
every checkpoint also carries an integrity hash over its own core
fields, so tampering with `charter_hash`, `org_id`, or `eval_time`
is rejected even on an unwitnessed, unsigned checkpoint (finding
M8). The integrity hash is an unkeyed seal: it detects
accidental or naive tampering, and it is not a signature. A
party who rewrites a whole unwitnessed, unsigned checkpoint can
recompute the seal, which is why external reliance requires
witness cosignatures (invariant I8).
`verify_checkpoint` is the stranger's recompute-or-reject check
(Section 16.7 step 3): it recomputes the checkpoint from the
named chain head and rejects any difference, and enforces the
policy's witness quorum where one is set. `effective_authority`
is the Section 16.1 minimum of grant, manifest, and Standing
ceiling.

Prototype choices where the specification leaves a numeric
parameter open (prototype choices, not specification language;
the specification fixes them at its day-30 freeze): default mint
rate 1, default burn unit 5, default burn multipliers 1, default
severe reason codes `revoked` and `scope`, default hop
attenuation 1,000,000 ppm (no attenuation), default epoch length
0 (a single epoch), and a default ceiling curve with tiers at
Standing 0, 1, 10, 50 and 200 whose tier 0 allows a small entry
budget per action (5 units) so a new agent can do the bounded
work that first mints Standing. The legacy prototype alias
encodings this tree once read (`hop_attenuation_percent`,
`correlated_burn_divisor`, the flat diversity keys,
`mint_per_action`, `burn_per_denial`) are retired as of repair
round 4: no implementation reads them, and the accepted policy
language is exactly the Section 16.10 fields both trees read.
The countersign requirement is read from exactly one encoding,
`countersign_policy` with a `required_for` list (Section 16.10
decision 22); any other shape or field name is a validation
error. A checkpoint built without witness signers still carries
an empty witness list and no signature, and is an internal-use
claim; where a policy sets a witness quorum, `verify_checkpoint`
rejects such a checkpoint.

## How to run the Provable Kill demo

```sh
cd code
python3 demo_provable_kill.py
```

The demo constitutes a small firm in-process: a rogue seat with a
genuine delegation works for a simulated 7 days of receipted,
counterparty-countersigned history (timestamps are data, generated
deterministically), alongside a child sub-delegation and a sibling
seat. The founder revokes the rogue delegation and the gate emits
the KILL-BURN checkpoint: the rogue's Standing recomputes to zero
in every class while the sibling's checkpoint recomputes unchanged.
The rogue then attempts a direct action, an action through the
child sub-delegation minted before the revocation, and a replay of
a previously valid authorisation; all three are denied with reason
code `revoked`, each carrying the Standing second ground, and the
sibling completes an action in the same window. The demo writes
`provable_kill_bundle.json`, verifies it in-process, and runs the
standalone verifier over it in a subprocess. Exit code 0 means
every expectation held.

## What is deliberately not built yet

- The ToolGate MCP proxy and any network transport. `toolgate/` is
  the in-process decision path only: pinning, the five decision
  checks, and receipt emission, with no server and no model in the
  loop.
- The Acta CLI (`init`, `log`, `verify`, `export`, `replay`) and
  replay-lite.
- External anchoring (RFC 3161 timestamping and transparency-log
  commitments). Witness cosigning of Standing checkpoints is
  implemented in the prototype (see above); anchoring the chain
  head with third parties is not.
- The Git and pull request adapter and the continuous integration
  receipt check.
- Asymmetric signing (Ed25519) behind the signer interface.
- Charter-chain revocation events as charter amendments: in this
  prototype a revocation is a REVOCATION receipt in the Acta chain
  naming the delegation-manifest id, and the gate reads revocation
  state from that chain. The charter tooling of Section 6.5 is not
  wired to it yet.
- Two blueprint fixture items remain uncovered, by the decision
  recorded in `../CORPUS-INDEX.md`: oversized or deeply nested
  receipts (blueprint 26) and integer overflow (blueprint 28).
  Neither implementation, and no specification section, fixes a
  size limit or an overflow rule for v0.1, so no honest expected
  verdict exists for either yet.
- A second, independent verifier implementation in a second language
  (specification ticket T9 requires a stranger to build it from the
  specification alone before launch).

## Audit repair round (2026-11-23)

The independent audit of 2026-11-23 (../AUDIT-2026-11-23.md)
graded this tree with findings C2 and M1 to M8. All are fixed
here, each with a regression test in `tests/test_audit_repair.py`
named for its finding: charter signatures are verified (C2);
`verify_chain` fails closed without a verifier (M1);
countersignatures are verified before they mint (M2); a severe
denial erases an epoch of mint with or without a cap, and
standing policies are validated against that rule (M3); a
KILL-BURN burns only the killed subtree (M4); recorded scope
carries the limits dimension (M5); frozen charter fields cannot
be amended and `standing_policy` and `anchoring` are required
(M6); the gate checks resources, operations, delegation validity
windows, epoch budgets, depth, and fanout (M7); and checkpoints
can be witnessed and verified by recomputation (M8).

## Re-audit repair round 2 (2026-11-23)

The re-audit (../REAUDIT-2026-11-23.md) graded several round-1
fixes partially closed and found the Python Standing computation
diverging from the amended specification. Round 2, with
regression tests in `tests/test_reaudit_repair.py` named for
their findings: the charter trust anchor is pinned by the caller
and never read out of the charter, and an empty predecessor set
authorises nothing (C2 residual); the countersigned descriptor
binds receipt identity and risk weight, in the computation, the
gate, and the demo (M2 residual); the freeze is cumulative, the
freeze list itself is frozen, and `org.founded` is immutable
(M6 residual); the gate enforces `external_calls`, checks depth
and fanout against the granting seat, supports signed delegation
manifests, and records the unsigned-manifest remainder above as
a stated limitation (M7 residual); checkpoints bind their
identity fields under an integrity hash (M8 residual); the
Standing computation is Section 16.10 exactly, the quadratic
burn closed form, `hop_attenuation_ppm`,
`correlated_burn_fraction_ppm` over segment classes, and the
`diversity_caps` object (N2); and the minors: the standalone
verifier requires `receipt_version` and rejects empty chains, as
does the library (r1, r5); string risk weights and negative
delegation depths are validation errors (r3); envelope key ids
bind to the verifier's key id (r4); unknown scope dimensions and
boolean limits are rejected (r6); correlated burn reaches
later-touched classes (r9); the gate never records an unverified
countersignature (r10). A cross-implementation differential test
(`tests/test_differential.py`) runs one generated chain and one
Section 16.10 policy through this computation and through the
Rust conformance runner and requires identical Standing vectors;
it caught two real divergences while being written (the Rust
correlated burn's reach, since fixed, and the diversity-cap
encoding home: Rust reads `diversity_caps` at policy level, this
prototype reads it at policy level by inheritance and per class,
and the differential uses the policy-level form both honour).

## Repair round 3 (2026-11-23)

The second re-audit (../REAUDIT2-2026-11-23.md) named the theme
composition: the two implementations must be one definition.
Round 3 fixes in this tree, each with a regression test in
`tests/test_repair_round3.py` named for its finding (the
cross-implementation cases live in `tests/test_differential.py`):

- **S1 (descriptor bytes).** The countersigned outcome
  descriptor is fixed by Section 16.10 decision 16 (exactly the
  fields agent_id, action_name, arguments_hash, receipt_id,
  result_hash, risk_weight, scope_class, timestamp, canonical
  JSON, absent fields null). This tree's bytes already matched
  that list; the Rust tree's did not. A pure-Python Ed25519
  signer now stands behind the Signer interface so real
  countersignatures cross between the trees in the differential
  test, in both directions. It is not constant-time and is not
  the production key path; the Rust tree is.
- **S3 (no invented defaults).** `compute_standing` states no
  default for any field Section 16.10 assigns to the policy: a
  missing burn_unit, mint_rate, half-life, ceiling curve, hop
  attenuation at depth, or burn multiplier is an
  UNSPECIFIED_BY_SPEC error. The prototype defaults are deleted,
  and the demo, the fixtures, and every test policy in this tree
  now state their policies completely. Fixture 11's policy was
  completed in the corpus and it now passes as spec conformance
  in both runners.
- **S4 (kill field).** One name everywhere: `killed_agent_ids`,
  in the gate's KILL-BURN receipts, in the computation, and in
  the Rust trees' native and prototype paths (decision 17).
- **S5 (witness quorum).** `verify_checkpoint` reads the quorum
  from the specification's witness policy form
  {witness_key_ids, quorum} (decision 15). It once read a
  `min_cosigs` field the specification never defined, and the
  round-1 repair's own test had encoded the wrong field; that
  test now uses the spec form, and a test here proves a
  `min_cosigs` field buys nothing.
- **S6 twin (duplicates).** `verify_chain` and the standalone
  verifier reject a duplicate receipt_id (DUPLICATE_RECEIPT_ID),
  and `compute_standing` raises on one: a countersignature
  cannot mint twice on duplicated descriptor identity. The Rust
  tree's S6 (the checkpoint integrity seal) is recorded in its
  README; this tree gained its seal in round 2.
- **Minors.** Dotted or unknown `frozen_fields` entries are
  charter validation errors (s1); `epoch_seconds` of 0 is an
  error (s5); per-class `diversity_caps` raises citing decision
  18, the policy level being the one placement both trees
  honour.

Stated positions on the re-audit's observations and the
outstanding r7 item:

- **Namespace disclosure (r7).** Section 3.1 requires layer
  data on Acta receipts inside `institutio.*` and `toolgate.*`
  namespaces. Neither tree namespaces its extension fields yet;
  they travel as the flat keys both trees read identically.
  Disclosed, not closed: namespacing is a wire-format change
  for the v0.2 receipt format, not a repair-round change.
- **Founder key rotation (o1).** Rotation of
  `amendment.authorized_key_ids` by a founder-signed amendment
  is authorised delegation under the specification, not a
  defect (decision 20). The shipped example charters in both
  trees now freeze the `amendment` object itself, so the
  examples cannot rotate; founders who want rotation leave it
  unfrozen and accept the delegation.
- **Descriptor context (o2).** Recorded at decision 19: the
  descriptor binds receipt content only in v0.1; receipt-id
  uniqueness is normative, and chain and organisation binding
  is v0.2 work.
- **Gate fanout (o3).** The gate's fanout check counts the
  child manifests registered under a parent manifest, not the
  children created inside one epoch; the specification's
  Section 7 wording is per epoch. This is a stated
  approximation in the prototype gate, recorded here rather
  than left unremarked; the epoch-scoped count belongs with
  the gate's epoch accounting work.
- **Differential blind spots (o4).** Closed for
  countersignatures and subtree kills by the S1 and S4 cases.
  Still open: policy-level diversity caps are not yet exercised
  through the runner's translated phase (they bind in the spec
  phase and in each tree's own tests).

## Repair round 4 (2026-11-23)

The convergence round, against the third re-audit
(`tests/test_repair_round4.py`, with the Rust halves in the
Rust tree's suites). Two new specification decisions govern
it: decision 22 (the one countersign-requirement encoding) and
decision 23 (the ceiling curve as a required field wherever
ceilings are produced).

- **T1 (countersign requirement encoding).** This tree once
  read only its own `countersign_required` field and never the
  `countersign_policy` field Section 16.3 item 4 names, minting
  at full weight under the specification's own encoding. It now
  reads exactly `countersign_policy` `{"required_for": [...]}`;
  every other shape, and the old field name anywhere, is a
  validation error. All shipped policies, tests, and the demo
  state the requirement in the decision 22 form.
- **T2 (duplicate receipt ids).** Already enforced in this
  tree at every entry point; the round brought the Rust tree
  to the same rule, and a differential case now proves both
  trees refuse the re-audit's duplicated-id segment.
- **t3 (policy value types).** Boolean and float values where
  integers are required are validation errors in this tree, as
  they already were in the Rust parser; nothing is coerced.
- **t4 (missing ceiling curve).** This tree's error is now
  the shared rule under decision 23; the Rust computation
  stops identically.
- **t5 (negative values).** A negative `burn_amount` is a
  validation error, never tallied; a negative `risk_weight`
  is a validation error, never silently computed as zero mint.
- **t6 (witness policy form).** A malformed `witness_policy`
  (a `k` alias, a string or missing quorum, a quorum outside
  decision 15's bounds) is an error at verification in this
  tree and a parse error in the Rust tree.
- **Alias retirement (o3).** Recorded in the Standing section
  above: the prototype-only alias dialects are retired, so the
  accepted policy language is identical in both trees.

## Repair round 5 (2026-11-23)

The strictness round, against the fourth re-audit
(`tests/test_repair_round5.py`, with the Rust halves in the
Rust tree's suites). One new specification decision governs
it: decision 24, the strictness table (integer, non-negative,
non-null, spec-named, eagerly and class-locally parsed),
implemented identically in both trees. The fourth re-audit's
27 divergent cases are permanent differential cases in that
file: this tree raises on every one, and the Rust runner may
not report any of them as spec conformance.

- **U1 (negative policy values).** This parser checked type
  but never sign, and a negative `burn_unit` or multiplier
  manufactured Standing (20 on 10 minted). Every quantity
  field is now sign-checked at parse.
- **U2 (scope and timing).** The class policy was a lazy
  top-level inheritance; it is now parsed eagerly, completely,
  and class-locally: top-level class fields take no effect,
  and a malformed value in an untouched class is an error
  before any computation. Shipped policies, the demo, and the
  example charter now state class fields (notably
  `correlated_burn_fraction_ppm`, decision 7's per-class field,
  and the charter example's `burn_unit`) inside their classes.
- **U3 and the T1 residue (nulls).** A stated null is an error
  for every policy field, including `countersign_policy`,
  which this tree once read as absent.
- **T2 residue.** A non-string `receipt_id` is a validation
  error here, as the Rust prototype parser now also makes it.
- **S2 residue.** A stated null `risk_weight` and
  `burn_amount` are errors in both trees; a null
  `burn_amount` was previously treated as zero by both.
- **S5 residue (witness policy at computation).** The
  computation validates `witness_policy` form and quorum
  bounds at entry, as verification always did. A consequence:
  a checkpoint can no longer be built under a malformed
  witness policy (building is a computation), so the round 3
  S5 test now builds under the spec-form policy and presents
  the malformed one at verification, where its assertion
  lives; `verify_checkpoint` recomputes without the witness
  policy so the form error is reported, not raised.
- **U4 (alias).** `severe_codes` inside a class is rejected
  here, as the Rust parser now rejects it; only
  `severe_reason_codes` is read.
- **U5 (timestamps).** Float and string timestamps were
  coerced with `int()` here and zeroed in Rust; both trees
  reject them, and negative timestamps and a malformed
  `eval_time` with them.
- **U6.** A list-form `scope_classes` crashed with an
  AttributeError; it is a policy error now.

Current result (2026-11-23, after repair round 5): 170 unit
tests run, 0 failures; fixtures 16 of 16; the Provable Kill
demo passes on 30 receipts.

## Repair round 6 (2026-11-23)

The residue round, against the fifth re-audit
(`tests/test_repair_round6.py`, with the Rust halves in the
Rust tree's suites). The fifth re-audit found the two
implementations in exact agreement on every well-formed
input, with the remaining distance confined to four residues
in this tree and one shared observation; all five are closed
here, so the round 5 sentence above, decision 24 implemented
identically in both trees, now stands as audited fact rather
than intent: the re-audit's residue probes were re-run after
these fixes and every one is rejected by both trees.

- **W1 (stated null identity fields).** A stated null
  `counterparty_id` or `subtree_root_id` was read as absence:
  the counterparty keyed diversity accounting as the string
  form of None, and the subtree fell back to the agent's own.
  Both fields are now read through a stated-null check, at
  receipt level and action level alike, as the Rust parser
  reads them.
- **W2 (witness policy at validation).**
  `validate_standing_policy`, the function charter
  validation calls, never examined `witness_policy`; it now
  applies decision 15's form and quorum bounds and rejects
  the `k` alias, with the same strictness as the computation
  and verification doors.
- **W3 (curve completeness).** The ceiling-curve validator
  checked only the tier fields present, so a tier missing
  `max_fanout` produced a silently incomplete ceilings
  entry. Every tier must now carry all six ceiling fields
  plus `min_standing` (decision 10), as the Rust parser has
  always required.
- **W4 (unknown receipt types).** `compute_standing`
  tallied an unknown receipt type, the re-audit's `TRANSFER`
  case, as nothing and returned a zero entry. It now raises
  INVALID_RECEIPT, matching Rust; the known inert types
  (GRANT, REVOCATION) remain accepted.
- **W5 (agent shape).** An agent stated as a bare string
  crashed this tree with an AttributeError and computed an
  empty result in Rust. Both trees now raise a validation
  error on any stated agent that is not the agent object;
  an absent agent field remains absence.

The five residue cases are permanent differential cases in
`tests/test_repair_round6.py`: this tree raises on every
one, and the Rust runner may not report any of them as spec
conformance.

Current result (2026-11-23, after repair round 6): 186 unit
tests run, 0 failures; fixtures 16 of 16; the Provable Kill
demo passes on 30 receipts.

## Design rules held throughout

- Deterministic behaviour: sorted keys in every canonical encoding,
  integer timestamps and integer arithmetic, no wall-clock reads
  inside verification.
- Every module imports without side effects.
- Dependency direction: `institutio` depends on `acta`; `toolgate`
  depends on `acta` and on `institutio.standing`; `acta` depends on
  nothing in this programme; the verifier depends on nothing at all.

## Fixture corpus expansion, Phase 1 (2026-11-23)

The corpus grew from 16 fixtures to 34: the blueprint's 30
enumerated fixtures plus the Provable Kill family K1 to K4, as
mapped in `../CORPUS-INDEX.md`. Two new fixture kinds were added
to the runner (`checkpoint` and `charter_chain`), both mirrored
in the Rust conformance runner, and the new Standing fixtures
(23, 24, and K1 as fixture 32) run as spec conformance in both
implementations and are pinned in the differential suite by
`tests/test_fixture_expansion.py`. No divergence was found: no
implementation code changed, and no existing fixture or test was
weakened. Two blueprint items (26 and 28) are recorded in the
index as uncovered remainder, with the reason for each.

Current result (2026-11-23, after the Phase 1 expansion): 190
unit tests run, 0 failures; fixtures 34 of 34; the Provable Kill
demo passes on 30 receipts.

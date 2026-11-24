# Acta and Institutio Rust Cores

Author: Gavin Blacklock

The Rust implementation of the Acta receipt core and the Institutio
charter and Standing layer, built to the combined v0.1
specification (`../SPEC-v0.1-and-90-day-plan.md`) and the
engineering blueprint's determinism rulebook (D1 to D20). The
Python prototype in `../code/` is the semantic reference; this
workspace is the shipping-core direction the blueprint names (Rust
primary, a spec-only second implementation to follow).

## Layout

```text
Cargo.toml                  workspace, lints, profiles
Cargo.lock                  committed: dependency pins are spec inputs (D10)
rust-toolchain.toml         pinned toolchain channel
run_tests.sh                every gate, one command
crates/
  acta-core/                the library
    src/cbor.rs             deterministic CBOR (RFC 8949 Section 4.2.1)
    src/signing.rs          DSSE PAE, Ed25519, HMAC (legacy path only)
    src/receipt.rs          receipt model, builder, CBOR form, native hash
    src/chain.rs            native hash-chain verification
    src/bundle.rs           JSON transport wrapper for native bundles
    src/legacy.rs           Python prototype compatibility path
    src/error.rs            typed errors with prototype-aligned codes
    tests/chain_tests.rs    unit and integration tests
    tests/property.rs       proptest property tests
  acta-verify/              the verifier crate
    src/main.rs             acta-verify: the one-file offline verifier
    src/bin/conformance.rs  fixture conformance runner
    tests/cli.rs            binary integration test
  institutio-core/          the Institutio layer (acta-core only)
    src/charter.rs          institutio.json model, validation, attenuation, hash chain
    src/policy.rs           standing_policy parsing and validation
    src/standing.rs         ComputeStanding, the one definition
    src/checkpoint.rs       StandingCheckpoint build, sign, witness, verify
    src/error.rs            typed errors, including UnspecifiedBySpec
    tests/charter_tests.rs  charter validation and signing tests
    tests/standing_tests.rs mint, burn, decay, ceiling, gap tests
    tests/provable_kill.rs  the Section 7 Provable Kill, end to end
    README.md               the Section 16 specification gap list
```

## What is implemented

1. **Deterministic CBOR** for machine objects: shortest-form
   integers and lengths, no indefinite lengths, map keys sorted by
   their encoded bytes. The decoder is validating: it rejects
   non-shortest forms, indefinite lengths, unsorted or duplicate
   keys, trailing bytes, floats, and tags. Reject, never repair.
2. **DSSE-style envelopes**: signatures are computed and verified
   over the Pre-Auth-Encoding of the payload type and the exact
   transmitted payload bytes, never over a re-serialisation.
3. **Real Ed25519 signatures** (ed25519-dalek, RFC 8032). Signing
   sits behind a `Signer` trait. Verification takes a pinned
   `TrustSet` as an explicit input: a signature counts only when
   it verifies under the pinned key for its claimed key id, and an
   envelope carrying a different key for a pinned key id is
   rejected as UNTRUSTED_KEY. The verifying key carried inside the
   envelope is never trusted on its own (audit finding C1, fixed
   2026-11-23; before the fix, a chain forged under an attacker
   key copying the expected key id string was accepted).
4. **The receipt model and hash chain**, with field semantics
   matching the Python prototype: GRANT, ACTION, DENIAL, plus the
   Standing derived types BURN, PROMOTION, DEMOTION, KILL-BURN and
   REVOCATION, matching the prototype's current type set. A DENIAL
   without a reason code from the Section 3.5 set (`revoked`,
   `scope`, `manifest-mismatch`, `budget`, `standing-ceiling`)
   cannot be built through the builder, and fails verification with
   the typed error `DenialReasonMissing` (code
   `DENIAL_REASON_MISSING`) when one is crafted by hand.
   The native receipt hash is domain-separated: SHA-256 over the
   per-type domain tag, the raw prior hash, and the canonical CBOR
   body (blueprint rule D7).
5. **Integer-only mathematics**: no float type exists in acta-core's
   types, clippy denies float arithmetic workspace-wide, and
   `run_tests.sh` greps for float types and for HashMap (BTreeMap
   only, rule D5) as a second, dumber gate.
6. **The one-file verifier**: `acta-verify BUNDLE.json
   --trust-file TRUST.json [--expected-head HEX]
   [--expected-length N]` prints one plain verdict and exits 0 or
   1 (2 for a malformed invocation). The trust file is a JSON
   object pinning the operator's keys,
   `{"keys": [{"key_id": "...", "verifying_key_hex": "..."}]}`;
   without it the verifier fails closed, and there is no mode in
   which a bundle authenticates itself. The bundle is a JSON
   transport wrapper; the signed payload inside it is base64
   deterministic CBOR, checked as exact bytes.

## Conformance against the Python prototype

Run:

```sh
cargo run --bin conformance -- ../code/fixtures ../code/fixtures/test_secret.txt
```

The prototype corpus is the conformance target. Three adaptations
apply, stated plainly:

1. **Receipt fixtures** are verified through acta-core's `legacy`
   module, which reproduces the prototype's canonical-JSON hashing
   and its HMAC-SHA256 placeholder signatures byte for byte, with
   the same check order and failure codes as the prototype's
   `verify_chain`. The native Rust format cannot be applied
   byte-for-byte to these files, by design: CBOR encoding, a
   domain-separated hash, and Ed25519 signatures produce different
   bytes for the same chain semantics. The semantics and the
   verdicts are the conformance target; the bytes are not, and any
   future cross-implementation vector corpus must be generated per
   encoding from the frozen specification (blueprint Section 2.4).
2. **The charter fixture** (fixture 05, child delegation exceeding
   its parent) is checked by institutio-core's structural charter
   validator, `validate_charter_structure`, and the expected error
   text is matched against its errors. The fixture charter carries
   the prototype's HMAC placeholder signature, which this tree
   cannot authenticate; its expected verdict is a structural
   rejection, which the structural check supplies. Authenticated
   validation (`validate_charter` against a pinned trust set) is
   exercised in institutio-core's own tests.
3. **Standing fixtures** (fixtures 11 and 14, kind `standing`) run
   against institutio-core's ComputeStanding, each tried first
   with its policy exactly as written (spec conformance) and then
   with its parameters expressed as an explicit policy
   (prototype-parameter conformance), the two labels never merged.
   Fixture 14 passes as spec conformance. Fixture 11 passed as
   prototype-parameter conformance only until repair round 3
   completed its policy in the corpus (finding S3); it now
   passes as spec conformance too. The full analysis, and the
   fifteen-item specification gap list it belongs to, are in the
   institutio-core README.

Current result (2026-11-23, after the Phase 1 corpus
expansion): 34 fixtures run, 34 passed, 0 failed, 0 skipped.
The prototype's original six fixtures are among the passes, each
with the expected failure code where the fixture is a negative
case. The corpus now totals the full blueprint set of 30
fixtures plus K1 to K4 (specification Section 3.6 names 25 or
more), as mapped in `../CORPUS-INDEX.md`, which also records
the two blueprint items (26 and 28) left as uncovered remainder
and the analogues used for items 21, 22, and 27. The runner
gained two fixture kinds for the expansion: `checkpoint`
(prototype checkpoint verification mirrored field for field,
with Standing recomputed by institutio-core) and `charter_chain`
(the structural chain check, under the same documented
adaptation as the single charter fixture).

## Tests

```sh
./run_tests.sh
```

That runs `cargo test` (unit tests in the library modules, chain
integration tests, four proptest properties: generated chains
verify; any single-byte payload tamper is detected; reordering is
detected; any single-byte signature tamper is detected as
SIGNATURE_INVALID; plus the institutio-core charter, Standing, and
Provable Kill suites), the conformance runner, clippy with warnings
denied, and the grep gates (no float types, no HashMap, in both
core crates). Tests need no network: dependencies are fetched once
by `cargo fetch` and pinned in Cargo.lock.

Current result (2026-11-23, after repair round 6):
86 tests run, 86 passed, 0 failed (32 acta-core and acta-verify,
including the 5 C1 regression tests, the 2 N3 CBOR hostile
input tests, and the 2 T2 duplicate receipt id tests, native
and legacy; 54 institutio-core: 15 charter, 37 Standing, 2
Provable Kill integration).

## Audit repair round (2026-11-23)

The independent audit of 2026-11-23 graded this tree with one
Critical finding, C1: the verifier authenticated signatures
against the key carried inside the untrusted envelope. C1 is
fixed here: `verify_chain` takes a pinned `TrustSet`, the CLI
requires `--trust-file` and fails closed without it, and the
audit's forged-chain attack is a regression test at both levels
(`crates/acta-core/tests/audit_repair.rs`,
`crates/acta-verify/tests/audit_repair_cli.rs`). Audit finding
M8 (checkpoint recompute-or-reject) lands for this tree in
institutio-core: `verify_checkpoint` in
`crates/institutio-core/src/checkpoint.rs` recomputes a
StandingCheckpoint and rejects any difference, with witness
cosignatures; it is not in acta-core because the checkpoint type
belongs to the Institutio layer and acta-core must not depend on
it (the one-way dependency rule).

## Re-audit repair round 2 (2026-11-23)

The re-audit (../REAUDIT-2026-11-23.md) found a new Critical in
this tree and graded M8 partially closed. Round 2 fixes, each
with a regression test named for its finding:

- **N1 (charter authentication).** `validate_charter` and
  `verify_charter` now verify envelope signatures against a
  pinned `TrustSet` and a caller-supplied authorised key set,
  never against the `verifying_key` carried inside the untrusted
  envelope; a carried key differing from the pinned key is
  rejected as UNTRUSTED_KEY. Unsigned and attacker-signed
  charters reject. The unauthenticated structural check is named
  what it is, `validate_charter_structure`. Required fields now
  include `standing_policy`, `anchoring`, and `org.founded`, and
  charter chains enforce the cumulative freeze, the frozen
  freeze list, and `org.founded` immutability, with amendments
  verified against the verified predecessor's authorised set and
  no fallback when that set is empty.
- **N3 (panics on hostile input).** The CBOR decoder rejects
  absurd declared lengths before allocating (checked arithmetic,
  a count-versus-remaining-bytes bound) and caps nesting depth;
  `compute_standing` returns a PolicyInvalid error for a zero
  half-life instead of dividing by zero. Regression tests carry
  the re-audit's exact probes.
- **N4 (countersigning is cryptographic).** ComputeStanding
  receives pinned counterparty keys and verifies
  `counterparty_sig` over the bound outcome descriptor (receipt
  id, arguments hash, result hash, risk weight), byte-identical
  to the Python prototype's descriptor. Presence-only
  countersignatures mint zero where required.
- **M8 residual.** `verify_checkpoint` rejects: an error, not a
  passive verdict, on recomputation mismatch, on an operator
  signature that fails under the pinned key for its claimed id,
  and on an unmet witness quorum.
- **Minors.** Empty chains are rejected by `verify_chain` (r5);
  correlated burn reaches classes first touched after the severe
  denial, per decision 7's segment wording (r9); unknown scope
  dimensions in attenuation are rejected (r6); a bare
  `hop_attenuation` of 0 is unspecified, as decision 6 requires
  (observation O2).

A cross-implementation differential test in the Python tree
(`code/tests/test_differential.py`) runs one generated chain and
one Section 16.10 policy through both implementations and
requires identical Standing vectors at spec conformance.

## Repair round 3 (2026-11-23)

The second re-audit (../REAUDIT2-2026-11-23.md) graded both
trees "sound with findings" and named the theme composition:
the two implementations must be one definition. Round 3 fixes,
each with a regression test named for its finding:

- **S1 (descriptor bytes).** The countersigned outcome
  descriptor carried the action name under the key `action` in
  this tree and `action_name` in the Python tree, under a written
  claim of byte-identity. Section 16.10 decision 16 now fixes the
  descriptor's exact field list; both trees produce those bytes,
  and the conformance runner accepts a fixture's
  `counterparty_keys` map, so a Python-produced countersignature
  verifies in this tree's computation (and a Rust-produced one
  in the Python tree's), proven in the differential test.
- **S2 (clamping).** `StandingReceipt::from_signed` returns a
  `Result` and rejects a negative delegation depth, risk weight,
  or burn amount as a parse error; it clamped depth to zero
  before, silently granting unattenuated mint.
- **S4 (kill field).** The kill-subtree list travels under the
  single name `killed_agent_ids` (decision 17) in the native
  verdict, the prototype path, and the Python tree; the
  prototype constructor once hardcoded an empty list.
- **S6 (checkpoint seal).** `StandingCheckpoint` carries an
  `integrity_hash` over its signing view, verified in
  `verify_checkpoint` before recomputation, binding the identity
  fields (charter hash, org id, evaluation time, and the rest)
  even for unwitnessed and unsigned checkpoints. The
  `internal_only` label stays, and now means what it says: no
  witnesses, but sealed and recomputable. The seal's limit,
  stated plainly: it is an unkeyed seal, so it detects
  accidental or naive tampering; a party who rewrites a whole
  unwitnessed, unsigned checkpoint can recompute the seal, and
  external reliance requires witness cosignatures (invariant
  I8). Signed or witnessed checkpoints are unaffected, because
  the attacker cannot re-sign.
- **Minors.** Dotted or unknown `frozen_fields` entries are
  validation errors (s1); `epoch_seconds` of 0 is a policy error
  in the computation (s5); a per-class `diversity_caps` is a
  parse error citing decision 18; a per-class `ceiling_curve`
  overrides the policy-level curve, as the Python tree has it
  (decision 21); the correlated burn fraction is required only
  when another class exists in the segment to burn (decision 7).

Stated positions on the re-audit's observations and the
outstanding r7 item:

- **Namespace disclosure (r7).** Section 3.1 of the
  specification requires layer data on Acta receipts to live
  inside `institutio.*` and `toolgate.*` namespaces. Neither
  implementation namespaces its extension fields yet; the fields
  travel as the flat verdict and receipt keys both trees read
  identically. This round discloses the gap rather than closing
  it: namespacing is a wire-format change that belongs with the
  v0.2 receipt format work, not inside a repair round, and until
  then the flat form is the one definition both trees share.
- **Descriptor context (o2).** The countersigned descriptor
  binds receipt content only; it names no chain or organisation.
  That is the recorded v0.1 position (decision 19): receipt ids
  are unique and duplicates are rejected, so a countersignature
  cannot mint twice on one identity; chain and organisation
  binding is v0.2 work. The rejection is this tree's own since
  repair round 4 (the third re-audit found it missing here and
  this statement false of this tree): `verify_chain` rejects a
  duplicated receipt_id as DUPLICATE_RECEIPT_ID on the native
  path and on the legacy prototype path, and institutio-core's
  ComputeStanding refuses a segment carrying one
  (`test_t2_duplicate_receipt_id_rejected` in acta-core, on both
  paths, and in institutio-core's standing tests).
- **Differential blind spots (o4).** The S1 and S4 cases above
  close the countersignature and subtree-kill blind spots. The
  differential still does not exercise policy-level diversity
  caps through the runner's translated phase; the caps bind in
  the spec phase of both trees and in each tree's own tests.

## Repair round 4 (2026-11-23)

The convergence round, against the third re-audit. Two new
specification decisions govern it: decision 22 (the one
countersign-requirement encoding) and decision 23 (the ceiling
curve as a required field wherever ceilings are produced).

- **T1 (countersign requirement encoding).** This tree once
  accepted four sub-forms of `countersign_policy` and ignored
  the Python tree's differently named field. The parser now
  accepts exactly `{"required_for": [class names]}` and rejects
  every other shape, a differently named field, and the field
  inside a scope class, as POLICY_INVALID
  (`test_t1_countersign_policy_other_forms_are_parse_errors`).
- **T2 (duplicate receipt ids).** Recorded under o2 above:
  rejected at native and legacy chain verification and at
  ComputeStanding, matching the Python tree and decision 19.
- **t4 (missing ceiling curve).** ComputeStanding now stops
  with UnspecifiedBySpec(CeilingCurve) where neither the class
  nor the policy states a curve, as the Python tree does
  (decision 23; `test_t4_missing_ceiling_curve_is_a_computation_error`).
- **t5 (negative burn amount).** A present negative or
  non-integer `burn_amount` on the prototype path is a parse
  error, never silently dropped
  (`test_t5_negative_burn_amount_is_a_parse_error`).
- **t6 (witness policy form).** The parser admits exactly
  `{witness_key_ids, quorum}`: no `k` alias, no missing-quorum
  default, no dropped non-string ids; decision 15's bounds are
  validation errors (`test_t6_malformed_witness_policy_is_a_parse_error`).
- **Policy language.** This tree never read the Python
  prototype's legacy alias encodings; the prototype retired
  them in this round, so the accepted policy language is now
  identical in both trees.

## Repair round 5 (2026-11-23)

The strictness round, against the fourth re-audit. One new
specification decision governs it: decision 24, the strictness
table (integer, non-negative, non-null, spec-named, eagerly and
class-locally parsed), implemented identically in both trees.

- **U3 (nulls).** This parser read a stated null class field as
  absent; the policy reader now errors on a stated null for
  every field, and the prototype receipt parser errors on a
  stated null `risk_weight` and `burn_amount` instead of
  defaulting them (`test_u3_null_policy_fields_are_parse_errors`,
  `test_u3_null_risk_weight_is_a_parse_error`).
- **T2 residue (non-string receipt identity).** A numeric
  `receipt_id` was silently erased at prototype parse; it is a
  parse error now (`test_t2_nonstring_receipt_id_is_a_parse_error`).
- **S5 residue (witness bounds at computation).**
  `compute_standing` checks decision 15's quorum bounds at
  entry, not only in `validate_policy` and at verification
  (`test_s5_witness_quorum_bounds_checked_at_computation`).
- **U4 (the `severe_codes` alias).** This parser honoured the
  undocumented alias and silently dropped its non-string
  entries; it is rejected, and only `severe_reason_codes` is
  read (`test_u4_severe_codes_alias_rejected`).
- **U5 (malformed timestamps).** Float, string, negative, and
  null prototype timestamps mapped to 0; they are parse errors
  (`test_u5_malformed_timestamps_are_parse_errors`), and the
  conformance runner rejects a non-integer fixture `eval_time`
  the same way. The runner's prototype-parameter translator no
  longer writes explicit nulls for absent parameters, which
  the table now rejects in a translated policy as in any other.

## Repair round 6 (2026-11-23)

The residue round, against the fifth re-audit. This tree was
the stricter side of every surviving item; its one change is
the shared observation W5, and the rest of the round is the
Python tree closing its four residues (W1 to W4), recorded
in that tree's README. The round 5 sentence above, decision
24 implemented identically in both trees, now stands as
audited fact rather than intent: the re-audit's residue
probes were re-run after the fixes and every one is rejected
by both trees, and the five cases are permanent differential
cases in the Python suite.

- **W5 (agent shape).** The prototype receipt parser read
  the agent id through the agent object without checking
  the shape, so an agent stated as a bare string read as an
  absent id and the computation silently returned an empty
  result, where Python crashed with an AttributeError. A
  stated agent that is not an object is now a parse error
  here and a validation error there
  (`test_w5_agent_as_string_is_a_parse_error`); an absent
  agent field remains absence.
- **W3 (curve completeness), checked.** This tree's parser
  already required all seven tier fields at parse; the rule
  is now pinned by a named test
  (`test_w3_tier_missing_a_field_is_a_parse_error`) matching
  the completeness check the Python validator gained.

Current result (2026-11-23, after repair round 6): 86 tests
run, 86 passed; conformance 16 of 16; clippy clean; the
no-float and no-HashMap grep gates pass.

## Fixture corpus expansion, Phase 1 (2026-11-23)

The conformance corpus grew from 16 fixtures to 34 (see
`../CORPUS-INDEX.md` for the blueprint mapping). The runner's
new `checkpoint` and `charter_chain` kinds are documented in
the runner source and in the corpus index. No divergence was
found in the expansion: the new Standing fixtures (23, 24, and
K1 as fixture 32) pass as spec conformance, and no library code
in this tree changed; only the conformance runner gained the
two kinds.

Current result (2026-11-23, after the Phase 1 expansion): 86
tests run, 86 passed; conformance 34 of 34; clippy clean; the
no-float and no-HashMap grep gates pass.

## Deliberately not built here

ToolGate (no crate yet), external anchoring (RFC 3161 and
transparency-log submission; checkpoint witnessing is built in
institutio-core, anchor submission is not), the Git and CI adapter,
and the Go second implementation. The verifier binary is a
debug-profile build in development; the blueprint's musl static
release build and reproducible-build verification are release
engineering, not yet done, and this README does not claim them.

# Fixture Corpus Index and Reconciliation

Author: Gavin Blacklock
Date: 2026-11-23

This index reconciles three numberings that do not agree with each
other, and states exactly what the corpus now contains.

## The three numberings

1. The engineering blueprint (research report of 2026-11-23,
   Section 4.1 and 4.2) enumerates 30 fixture items, of which item
   25 is the Provable Kill set, itself four fixtures K1 to K4.
2. The specification (Section 3.6) requires at least 25 fixtures
   and names the attack classes, not numbers.
3. The shipped corpus numbers its files in the order they were
   built: `fixture_01` to `fixture_34` in
   `code/fixtures/`. Corpus file numbers are not blueprint numbers.

The corpus total is 34 fixture files: the 30 blueprint items are
covered as mapped below (28 directly or by a stated analogue, 2
recorded as uncovered remainder), the Kill family K1 to K4 is
included inside that mapping, and 4 further fixtures shipped
before the blueprint enumeration (02, 06, 07, 16) are surplus
coverage of specification Section 3.6 classes. Every fixture runs
in both implementations: the Python runner
(`code/fixtures/run_fixtures.py`) and the Rust conformance runner
(`code-rust/crates/acta-verify/src/bin/conformance.rs`). Result
after this expansion: 34 run, 34 passed in both.

## Format reconciliation

The blueprint's Section 4.1 directory form (a directory per
fixture holding `fixture.json`, `expected.json`, and `README.md`)
and the corpus's established form (one self-contained
`fixture_XX_<slug>.json` file stating its input, its expected
verdict, its reason code or expected Standing, and its expected
chain head, consumed identically by both runners since fixture 01)
conflicted. Resolution, stated once: the single file remains the
canonical runner input, because both runners, the deterministic
generator (`fixtures/generate_fixtures.py`), and six audit rounds
are built on it, and two canonical inputs would drift. The
blueprint directory form is provided as a generated mirror in
`code/fixtures/corpus/F-###-<slug>/` for all 34 fixtures:
`fixture.json` is a byte copy of the canonical file,
`expected.json` is the extracted expectation (verdict, reason
code or error text, expected Standing or last receipt, chain
head, and, for checkpoint fixtures, the checkpoint head and
Standing vector), and `README.md` states the attack and what a
wrong implementation would do. The mirror carries no authority;
if it and the canonical file ever differ, the canonical file wins.

## Blueprint item to fixture mapping

| Blueprint | Fixture file | Notes |
|---|---|---|
| 1 valid clean chain, mint to cap | fixture_01, fixture_23 | 23 states the mint cap saturation explicitly |
| 2 expired delegation | fixture_17 | charter manifest expiring at its own issue time |
| 3 delegation exceeding charter | fixture_05 | attenuation violation, charter kind |
| 4 scope-widening tool manifest, pin mismatch | fixture_15 | manifest-mismatch denial receipt |
| 5 tool not in manifest | fixture_18 | scope denial receipt for an unlisted tool |
| 6 DENIAL without reason code | fixture_04 | producer and verifier both reject |
| 7 DENIAL with unknown reason code | fixture_10 | |
| 8 replayed receipt | fixture_21 | duplicate receipt id, DUPLICATE_RECEIPT_ID |
| 9 reordered receipts | fixture_03 | |
| 10 truncated chain, missing middle | fixture_22 | detected as a sequence gap, REORDERED |
| 11 forked chain | fixture_08 | |
| 12 signature over wrong payloadType | fixture_19 | INVALID_ENVELOPE |
| 13 truncated or PAE-length-manipulated envelope | fixture_20 | TAMPERED |
| 14 valid signature, wrong key | fixture_12 | also K4, below |
| 15 BURN arithmetic to zero, then spend | fixture_11 | |
| 16 decay boundary at an epoch edge | fixture_14 | |
| 17 Standing cap and floor saturation | fixture_23 | cap; fixture_11 states the zero floor |
| 18 countersignature missing or forged on a mint | fixture_24 | missing countersignature mints nothing |
| 19 witness cosignatures 2 of 5, below quorum | fixture_25 | checkpoint kind, quorum 3 of 5 |
| 20 checkpoint with 3 of 5 valid | fixture_26 | checkpoint kind |
| 21 anchor for a different hash | fixture_27, analogue | see below |
| 22 transparency-log split view | fixture_28, analogue | see below |
| 23 charter amendment, valid succession | fixture_29 | charter_chain kind |
| 24 amendment by non-successor, broken hash link | fixture_30 | broken predecessor link, charter_chain kind |
| 25 Provable Kill set | fixtures 32, 33, 34, and 12 | K1 to K4, below |
| 26 oversized or deeply nested receipt | not covered | uncovered remainder, see below |
| 27 duplicate or non-canonical encoding | fixture_13, analogue | see below |
| 28 integer overflow in amounts or Standing | not covered | uncovered remainder, see below |
| 29 unknown receipt type | fixture_09 | |
| 30 kill switch, then an attempted action | fixture_31 | KILL-BURN receipt, then a revoked denial |

## Provable Kill family

| Kill fixture | Fixture file | Expected result |
|---|---|---|
| K1 | fixture_32 | kill is absorbing: post-kill actions restore no Standing, Standing 0 |
| K2 | fixture_33 | replay of a pre-kill authorisation after the revocation receipt is denied, reason code revoked |
| K3 | fixture_34 | a fork omitting the kill fails against the true chain head, TRUNCATED |
| K4 | fixture_12 | a kill signed by the wrong key is invalid, KEY_ID_MISMATCH; this fixture predates the expansion |

The blueprint's K1 text names a denial reason `KILLED`. The
specification's frozen reason code set (Section 3.5, extended by
Section 16) contains no such code, and the specification governs:
K1 is therefore proven on the Standing ground (a KILL-BURN zeroes
the seat and later actions mint nothing, fixture_32) and the
denial side of the family uses the `revoked` code (fixtures 31
and 33). This is a blueprint-to-specification conflict recorded
here, not a silent substitution.

## Analogues, stated plainly

- Blueprint 21 and 22 (an RFC 3161 token for a different hash; a
  transparency-log split view): neither implementation carries
  RFC 3161 or transparency-log proof verification. The Rust
  README already states anchor submission is not built, and the
  specification's ticket T4 remains open work. Fixtures 27 and 28
  exercise the same binding property with the mechanisms that do
  exist: a checkpoint whose chain head binds a different chain is
  rejected on recomputation (27), and a forked prefix presented
  against an anchored expected head is rejected as TRUNCATED
  (28). They do not prove TSA or log proof verification, and no
  report may cite them as doing so.
- Blueprint 27 (duplicate CBOR key, non-canonical CBOR): the
  prototype corpus's wire encoding is canonical JSON inside the
  DSSE envelope, not CBOR. Fixture_13 (a non-canonical envelope
  payload) is the same attack in this corpus's encoding. The
  native Rust CBOR decoder has its own unit and property tests;
  a corpus fixture for it would need a native-format fixture
  kind, which neither runner consumes today.

## Uncovered remainder

- Blueprint 26 (oversized or deeply nested receipt): neither
  implementation defines a size or depth limit, and the
  specification fixes none for v0.1, so there is no expected
  verdict to state. A fixture here would manufacture semantics.
  Recorded as a specification gap for the next amendment round.
- Blueprint 28 (integer overflow): the same position. Python
  integers are unbounded and the Rust Standing parser rejects
  values outside its integer types at parse, so the two trees
  already differ in what an out-of-range input even is; until
  Section 16.10 fixes an overflow rule, no honest shared
  expectation exists. Recorded as a specification gap, and as
  the one known acceptance-surface asymmetry the corpus does
  not cover.

## New fixture kinds added by this expansion

- `checkpoint`: the fixture carries Standing receipts, a complete
  standing policy including a witness policy, and a checkpoint
  built by the prototype's `build_checkpoint`. The Python runner
  verifies it with `verify_checkpoint`; the Rust runner mirrors
  that verification field for field (integrity hash over the
  canonical core, recomputation of every computed field, HMAC
  witness cosignatures under the shared fixture secret, quorum
  counting), with Standing recomputed by institutio-core.
- `charter_chain`: the fixture carries a list of signed charters.
  The Python runner runs `validate_charter_chain` with the
  pinned founder key set. The Rust runner runs the structural
  chain check (per-charter structure, predecessor linkage over
  `compute_charter_hash`, cumulative freeze, founding-date
  rule), the same documented adaptation the single charter
  fixture has always used, because the prototype's HMAC charter
  signatures cannot be authenticated on the Rust legacy path;
  authenticated chain validation is exercised in
  institutio-core's own tests.

## Differential status

Every Standing-exercising fixture (11, 14, 23, 24, 32) is a
permanent member of the differential suite: the Rust conformance
runner reports each as spec conformance, and
`code/tests/test_fixture_expansion.py` pins that label, the
34-of-34 totals in both runners, and the new kinds, so a future
change that drops a fixture or demotes one to
prototype-parameter conformance fails the suite.

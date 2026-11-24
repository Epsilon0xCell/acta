# Acta, ToolGate, Institutio: the Go second implementation

Author: Gavin Blacklock
Licence: Apache License 2.0
Status: Phase 2 build, the independent Go implementation of the
v0.1 specification (`../SPEC-v0.1-and-90-day-plan.md`), written
from the specification text alone (blueprint Section 1.3: the
second implementation is spec-only, with no shared code and no
transliteration of the Python or Rust trees; those trees were run
as oracles for the differential, and their READMEs were read for
the documented adaptations, nothing more).

## Layout

```text
go.mod                      module acta-go, Go 1.23, no dependencies
internal/
  canon/                    strict JSON value model and the canonical
                            JSON encoder (sorted keys, no whitespace,
                            non-ASCII escaped), with duplicate-key
                            rejection and exact scalar kinds
  acta/                     the receipt core: DSSE Pre-Auth-Encoding,
                            envelope signing and verification over
                            exact bytes, the hash chain, and chain
                            verification with the corpus failure codes
  institutio/               the constitution layer:
    policy.go               standing_policy parsing and validation,
                            Section 16.10 decisions 1 to 15 and 18
                            to 24 (the strictness table included)
    standing.go             ComputeStanding, integer-only, checked
                            arithmetic, decisions 1 to 24
    checkpoint.go           StandingCheckpoint build and the
                            recompute-or-reject verification of
                            Section 16.7, with witness quorum
    charter.go              institutio.json structural validation,
                            delegation attenuation, amendment chains
cmd/
  acta-verify/              the one-file offline verifier (below)
  conformance/              the fixture conformance runner
tools/
  oracle_standing.py        differential harness: the Python oracle
  differential.py           the three-way differential driver
run_tests.sh                every gate, one command
DIFFERENTIAL.md             differential method and resolutions
```

Dependency direction follows Section 2.1: `institutio` depends on
`acta`, `acta` depends on nothing in this programme, and both
depend only on `canon` and the Go standard library.

## Dependencies: standard library only, by decision

This module has no third-party dependencies, and `go.mod` carries
no `require` lines. Ed25519 is `crypto/ed25519`, SHA-256 is
`crypto/sha256`, HMAC is `crypto/hmac`, and big-integer arithmetic
for exact attenuation is `math/big`, all from the standard
library. The blueprint's determinism rulebook (D10) treats a
dependency's serialisation change as a specification change; a
verifier a stranger must trust should have no serialisation
dependency at all. The canonical encoder is therefore implemented
in this tree (`internal/canon`), where its byte output is pinned
by tests, rather than imported.

## Signing paths: native and legacy

The native path is the specification's: DSSE-style typed
envelopes (Section 2.2) with Ed25519 signatures computed over the
Pre-Auth-Encoding of the payload type and the exact payload
bytes, verified against keys the caller pins, never against a key
carried inside the envelope. Receipt hashes are SHA-256 over the
exact payload bytes.

The corpus's legacy prototype format requires a compatibility
path, stated honestly, mirroring how the Rust tree documents its
legacy module: the fixture corpus signs canonical JSON payloads
with HMAC-SHA256 placeholder signatures under a published test
secret, because the Python prototype is standard-library only and
its language ships no asymmetric signature algorithm. The Go
legacy path reproduces that format's semantics: canonical JSON
payloads, the same Pre-Auth-Encoding, the same hash, the same
check order and the same failure codes. Semantics and verdicts
are the conformance target on this path, not bytes; the native
format differs in bytes by design (Ed25519 signatures), exactly
as the Rust tree records for its own legacy module. Charter
fixtures are checked on the documented structural adaptation the
Rust tree also uses (structure, attenuation, predecessor linkage
over the charter hash, cumulative freeze, founding-date rule),
because authenticated charter validation on the legacy path is
exercised in this module's own tests with native keys. Checkpoint
fixtures are verified field for field: integrity seal over the
canonical core, recomputation of every computed field, HMAC
witness cosignatures under the shared fixture secret, and quorum
counting (Section 16.7).

## ComputeStanding

`internal/institutio` implements Section 16 as amended by
Section 16.10 decisions 1 to 24: mint from countersigned,
in-ceiling ACTION receipts only, scaled by risk weight and
attenuated per delegation hop in exact integer arithmetic;
per-epoch mint caps and the three diversity caps; the quadratic
burn closed form (`burn_unit` times multiplier times the square
of the denial's ordinal in its class) with correlated burn across
every other class the agent touches in the segment; decay in
whole half-lives per mint event; burns that never decay; the
absorbing KILL-BURN (decision 17's single field name,
`killed_agent_ids`); ceiling curves at policy level with per-class
override (decisions 10, 21, 23); the one countersign-requirement
encoding (decision 22) with decision 16 descriptor bytes verified
as Ed25519 signatures against pinned counterparty keys; and the
decision 24 strictness table applied eagerly and class-locally
to every policy and receipt scalar. Policy changes the
computation refuses to invent are `UNSPECIFIED_BY_SPEC` errors,
never defaults.

## The offline verifier

`acta-verify` builds to a single static binary:

```sh
go build -o bin/acta-verify ./cmd/acta-verify

# Legacy corpus bundles (HMAC placeholder signatures):
bin/acta-verify BUNDLE.json --secret-file ../code/fixtures/test_secret.txt --key-id acta-test-key-1

# Native bundles (Ed25519, pinned keys, fails closed without them):
bin/acta-verify BUNDLE.json --trust-file TRUST.json [--expected-head HEX] [--expected-length N]

# Standing computation and checkpoint verification:
bin/acta-verify standing CASE.json [--counterparty-keys KEYS.json]
bin/acta-verify checkpoint CASE.json --secret-file ../code/fixtures/test_secret.txt
bin/acta-verify validate-policy POLICY.json
```

It prints one plain verdict line and exits 0 or 1 (2 for a
malformed invocation). There is no mode in which a bundle
authenticates itself.

## Tests and gates

```sh
./run_tests.sh
```

That builds both binaries, runs `go vet`, runs the Go unit tests
(PAE golden bytes, native Ed25519 chain signing and tamper
detection, mint and cap saturation, the burn closed form, whole
half-life decay, countersignature minting, the absorbing kill,
the strictness table, checkpoint quorum and recomputation, and
charter attenuation and expiry), runs the full 34-fixture corpus
through the Go conformance runner, runs the Python differential
and repair-round suites as the Python-Rust oracle leg, runs the
three-way differential (50 cases, see DIFFERENTIAL.md), and
scans every file in this tree for em dashes. It ends with an
explicit OVERALL verdict line.

Current result (2026-11-23): Go unit tests pass; conformance 34
of 34; three-way differential 50 cases, 50 in agreement, 0
disagreements, with 2 Rust legs skipped for documented runner
reasons (DIFFERENTIAL.md).

## Deliberately not built here

ToolGate's MCP proxy and network transport, external anchoring
submission (RFC 3161 and transparency-log clients), the Git and
CI adapter, and CBOR: the specification's v0.1 payload encoding
is JSON inside the DSSE envelope, and the corpus's wire encoding
is canonical JSON, so no CBOR codec is required by the frozen
specification or the corpus. The blueprint's deterministic CBOR
rule applies to a future native wire format, which would be a
specification amendment, not an implementation choice.

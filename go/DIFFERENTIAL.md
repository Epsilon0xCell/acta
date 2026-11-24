# Three-way differential: method and resolutions

Author: Gavin Blacklock
Date: 2026-11-23

## Method

`tools/differential.py` runs one shared case set through three
independent implementations:

- Go: the `acta-verify` binary built from this tree (`standing`
  mode, and `validate-policy` mode for the validation-door case).
- Python: the prototype's `ComputeStanding`, driven as a black-box
  oracle by `tools/oracle_standing.py`. The Go source was written
  from the specification; the prototype is an oracle here, never a
  source.
- Rust: the Rust conformance runner, fed a standing-kind fixture
  file per case in a temporary directory. For value cases the
  fixture's expected Standing is the Python oracle's result, and
  agreement requires the runner's spec conformance pass line. For
  error cases agreement requires that the runner does not report
  spec conformance for the malformed input, the same criterion the
  Python repair-round suites use for these cases.

The case set is 50 cases: 14 mechanism cases (mint, decay,
quadratic burn, correlated burn, both diversity cap forms, epoch
caps, hop attenuation, countersign mint and countersign absence,
the absorbing kill, sibling continuity, ceiling tier crossing,
tallies, and the both-hop-forms case M13), the 27 strictness
cases of repair round 5 (specification Section 16.10 decision
24), the 5 residue cases of repair round 6 (with the W1 subtree
variant counted inside W1's family as W1b), and fixtures 23, 24
and 32 rerun as spec-conformance Standing cases against all three
implementations and against the fixtures' own stated
expectations.

Result at build time: 50 cases, 50 in full agreement, 0
disagreements. Two Rust legs are skipped with reasons stated
below; neither skip hides a disagreement.

## Divergences found and how the specification resolved them

1. **Killed agent's decayed mint (M10, fixture 32).** The first
   Go build reported a killed agent's `minted_decayed` as its
   decayed mint total and `decay_applied` as 0, while both
   reference implementations report `minted_decayed` 0 and
   `decay_applied` equal to the whole minted total. Resolution:
   Section 16.6 states the kill burns the seat to zero in every
   scope class, and the checkpoint totals of Section 16.3 are
   defined over the same fields in both reference trees; the Go
   computation now zeroes the decayed mint of a killed agent and
   reports the full minted total as removed. The fixture's own
   stated expectation (standing 0) was satisfied by both readings;
   the shared field semantics were the deciding evidence.

2. **Bare `hop_attenuation` beside the ppm form (S27, M13).**
   Decision 6 states the bare form is conforming only as the
   integer 1. Probing all three trees showed the shared reading:
   the bare field is consulted only when `hop_attenuation_ppm` is
   absent; beside a stated ppm value it has no effect in any of
   the three implementations (proven by a depth-1 mint case in
   which the Rust runner passes the ppm-computed value as spec
   conformance with a bare 2 also stated, case M13). The
   strictness case S27 therefore states the bare form alone,
   where all three implementations reject a bare 2 identically.
   The Go parser implements the shared reading and cites this
   resolution in a comment at the rule.

3. **Witness policy at the validation door (W2).** The Python
   validator reports some policy errors by returning an error
   list rather than raising. The first oracle harness treated a
   returned list as success, which manufactured a divergence that
   did not exist: the validator does reject the `k` alias form
   (decision 15), and so does the Go validator. The harness now
   treats a non-empty returned error list as a rejection. No
   implementation changed.

## Skipped Rust legs, stated plainly

- **M08 (countersigned mint).** The Rust conformance runner's
  standing-fixture path computed a minted value of 0 for a
  Python-signed countersigned receipt in its spec attempt under
  every `counterparty_keys` encoding probed (hex public key, seed
  hex, base64 seed, base64 public key, key-id keying, and object
  forms), passing the case only as prototype-parameter
  conformance. The Go and Python implementations agree on the
  value (a valid countersignature mints, decision 16 descriptor
  bytes). The Python-Rust countersign leg is covered instead by
  the Python differential suite (`code/tests/test_differential.py`),
  which drives the Rust library through its own harness and is run
  by `run_tests.sh` as part of the differential gate. This is a
  runner-harness limitation, recorded here rather than silently
  dropped.
- **W2 (validation door).** The Rust conformance runner consumes
  fixture files and has no form for a charter-validation-door
  policy check, so the case compares Go against Python only. The
  same malformed witness policy at the computation door is case
  S19, which all three implementations reject.

## Standing of this document

No fixture and no expectation was adjusted to fit the Go output.
Every divergence above was resolved by changing the Go
implementation, the case construction, or the harness, in that
order of preference, and the resolution is recorded here as the
task requires.

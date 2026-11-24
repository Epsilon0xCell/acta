# Acta

Author: Gavin Blacklock
Status: v0.1 working specification and implementations, 2026-11-23

Acta makes every AI-agent action leave a signed, replayable receipt: no receipt, no trust.

Acta is a local-first, framework-neutral receipt format, a hash-chained ledger format, and an offline verifier. A receipt binds who delegated an action, which agent and model acted, what capability scope was granted, what action was taken, what the result was, and what changed. Receipts are portable artifacts: they can travel with the pull request, the commit, the dataset, the incident report, or the audit bundle they describe.

Acta is the evidence layer of a three-layer programme. ToolGate enforces, Acta proves, Institutio constitutes. The combined v0.1 specification is included in full in this repository under `spec/`, because the section structure makes splitting it artificial.

## What is in this repository

- `spec/`: the full combined v0.1 specification, including the Acta sections (Sections 3 and 4), the shared components, and Annex A, the claims ceiling that binds every public statement about this programme.
- `rust/`: the primary implementation. `acta-core` implements the receipt model, deterministic encoding, DSSE-style typed envelopes, Ed25519 signing, and hash-chain verification. `acta-verify` is the offline verifier and fixture conformance runner. The workspace also carries `institutio-core`, because `acta-verify` as built uses it for the Standing and checkpoint conformance forms; the home repository for that crate is `institutio`.
- `python-prototype/`: the Python reference prototype, clearly labelled as a prototype. It is the semantic reference used during development and is not the primary implementation.
- `go/`: the second implementation, in Go, including its own verifier. Two independent implementations are the credibility test this format sets for itself.
- `fixtures/`: the full shared attack-fixture corpus, 34 fixtures, in both directory form (`fixtures/corpus/`) and the single-file runner form, with `CORPUS-INDEX.md` reconciling the numbering. This repository is the one home of the shared corpus for the whole programme.
- `LICENSE`: the Apache License 2.0.
- `NO-RELICENSE-PLEDGE.md`: the written, irrevocable promise never to relicense the core.
- `SECURITY.md`: how to report a vulnerability.

## What a receipt can and cannot show

A verified receipt chain shows that the receipts in the file presented have the signatures, hashes, and chain order the format requires, and that cited artifacts match their recorded hashes where the verifier checks them. It does not show that an agent was safe, honest, or competent, and no statement in this repository claims otherwise. Claims about this programme are limited to the receipt-anchored forms permitted by Annex A of the specification.

## Licence

Code and specification text are licensed under the Apache License 2.0. Trademarks are held personally by the author and are not licensed by the Apache License 2.0.

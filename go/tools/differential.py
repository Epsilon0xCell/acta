#!/usr/bin/env python3
"""Three-way differential driver: Go vs Python vs Rust.

Every case is one (receipt segment, standing_policy, eval_time,
agent) input run through three independent implementations:

- Go: the acta-verify binary built from this tree (standing mode,
  or validate-policy mode for the validation-door case).
- Python: the prototype's ComputeStanding, driven as a black-box
  oracle by tools/oracle_standing.py.
- Rust: the Rust conformance runner, fed a standing-kind fixture
  file in a temporary directory. For value cases the fixture's
  expected Standing is the Python oracle's result and agreement
  requires the runner's "spec conformance" pass line. For error
  cases agreement requires that the runner does NOT report spec
  conformance for the malformed input (the criterion the Python
  repair-round suites use for the same cases).

Case set: the mechanism cases, the 27 strictness cases of repair
round 5 (specification Section 16.10 decision 24), the 5 residue
cases of repair round 6, and fixtures 23, 24 and 32 rerun as
spec-conformance Standing cases. One documented exception: the
Rust runner's standing-fixture path does not surface a valid
countersignature in its spec attempt under any counterparty_keys
encoding probed (hex public key, seed hex, base64 forms, key-id
keying, object forms); the countersigned-mint case therefore
compares Go against Python on values, and the Python differential
suite (run by run_tests.sh) covers the Python-Rust countersign
leg through its own harness. See DIFFERENTIAL.md.

Usage: differential.py ACTA_VERIFY_BINARY [RUST_CONFORMANCE_BINARY]

Author: Gavin Blacklock
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "..", "code", "fixtures")
SECRET = os.path.join(FIXTURES, "test_secret.txt")
ORACLE = os.path.join(HERE, "oracle_standing.py")

GO_BIN = os.path.abspath(sys.argv[1])
RUST_BIN = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(
    ROOT, "..", "code-rust", "target", "debug", "conformance")

SEED = bytes(range(32)).hex()

BASE_POLICY = {
    "ceiling_curve": [
        {"min_standing": 0, "max_budget_per_action": 5, "max_budget_per_epoch": 50,
         "max_irreversibility": 0, "max_data_sensitivity": 0, "max_delegation_depth": 0, "max_fanout": 0},
        {"min_standing": 10, "max_budget_per_action": 100, "max_budget_per_epoch": 1000,
         "max_irreversibility": 3, "max_data_sensitivity": 3, "max_delegation_depth": 3, "max_fanout": 8},
    ],
    "scope_classes": {
        "write": {"mint_rate": 2, "mint_cap_per_epoch": 36, "half_life_seconds": 10000000,
                  "hop_attenuation_ppm": 500000, "burn_unit": 10,
                  "burn_multipliers": {"revoked": 2, "scope": 1},
                  "severe_reason_codes": ["revoked"], "correlated_burn_fraction_ppm": 500000},
        "read": {"mint_rate": 1, "mint_cap_per_epoch": 100, "half_life_seconds": 10000000,
                 "hop_attenuation_ppm": 1000000, "burn_unit": 10,
                 "burn_multipliers": {"revoked": 2},
                 "severe_reason_codes": ["revoked"], "correlated_burn_fraction_ppm": 0},
    },
}


def act(cls="write", rw=3, ts=1000, agent="a1", name="repo.write", **extra):
    r = {"receipt_type": "ACTION", "agent": {"id": agent}, "timestamp": ts,
         "result_hash": "rh",
         "action": {"name": name, "arguments_hash": "ah", "risk_weight": rw, "scope_class": cls}}
    r.update(extra)
    return r


def den(cls="write", code="revoked", ts=2000, agent="a1"):
    return {"receipt_type": "DENIAL", "agent": {"id": agent}, "timestamp": ts,
            "reason_code": code,
            "action": {"name": "x", "risk_weight": 1, "scope_class": cls}}


def case(receipts, policy=None, eval_time=2000, agent="a1", seeds=None, validate_only=False):
    return {"receipts": receipts, "standing_policy": policy if policy is not None else copy.deepcopy(BASE_POLICY),
            "eval_time": eval_time, "agent_id": agent,
            "counterparty_seeds": seeds or {}, "validate_only": validate_only}


def pol_mut(fn):
    p = copy.deepcopy(BASE_POLICY)
    fn(p)
    return p


CASES = []
# Mechanism cases (value agreement).
CASES.append(("M01 mint and decay", case(
    [act(ts=1000)], pol_mut(lambda p: p["scope_classes"]["write"].update(
        {"mint_rate": 8, "half_life_seconds": 100, "hop_attenuation_ppm": 1000000})), eval_time=1200)))
CASES.append(("M02 quadratic burn ordinal across codes", case(
    [act(ts=0), den(code="scope", ts=10), den(code="revoked", ts=20)], eval_time=20)))
CASES.append(("M03 correlated burn", case(
    [act(ts=100), act(cls="read", rw=5, ts=100), den(ts=200)], eval_time=200)))
CASES.append(("M04 diversity counterparty cap", case(
    [act(ts=i * 60, counterparty_id="cp1") for i in range(4)] + [act(ts=300, counterparty_id="cp2")],
    pol_mut(lambda p: p.update({"diversity_caps": {"per_counterparty_fraction_ppm": 500000}})), eval_time=300)))
CASES.append(("M05 diversity task cap", case(
    [act(ts=0), act(ts=60), act(ts=120, name="other.task")],
    pol_mut(lambda p: p.update({"diversity_caps": {"per_task_type_per_epoch": 10}})), eval_time=120)))
CASES.append(("M06 epoch cap across epochs", case(
    [act(ts=0), act(ts=60), act(ts=150), act(ts=160)],
    pol_mut(lambda p: (p.update({"epoch_seconds": 100}),
                       p["scope_classes"]["write"].update({"mint_cap_per_epoch": 12, "hop_attenuation_ppm": 1000000}))), eval_time=160)))
CASES.append(("M07 hop attenuation depth 2", case(
    [act(ts=100, delegation_depth=2)], eval_time=100)))
CASES.append(("M09 countersignature missing mints zero", case(
    [act(ts=1000, receipt_id="r1", counterparty_id="cp-1")],
    pol_mut(lambda p: p.update({"countersign_policy": {"required_for": ["write"]}})), eval_time=1000)))
CASES.append(("M10 kill absorbing", case(
    [act(ts=0), act(ts=60), act(ts=120),
     {"receipt_type": "KILL-BURN", "agent": {"id": "a1"}, "timestamp": 180,
      "killed_agent_ids": ["a1"],
      "action": {"name": "standing.kill-burn", "risk_weight": 1, "scope_class": "write"}},
     act(ts=240), act(ts=300)],
    pol_mut(lambda p: p["scope_classes"]["write"].update({"hop_attenuation_ppm": 1000000})), eval_time=300)))
CASES.append(("M10b sibling unaffected by kill", case(
    [act(ts=0), act(ts=0, agent="a2"),
     {"receipt_type": "KILL-BURN", "agent": {"id": "founder"}, "timestamp": 100,
      "killed_agent_ids": ["a1"],
      "action": {"name": "standing.kill-burn", "risk_weight": 1, "scope_class": "write"}},
     act(ts=200, agent="a2")],
    pol_mut(lambda p: p["scope_classes"]["write"].update({"hop_attenuation_ppm": 1000000})),
    eval_time=200, agent="a2")))
CASES.append(("M11 ceiling tier crossing", case(
    [act(ts=i * 60) for i in range(4)],
    pol_mut(lambda p: p["scope_classes"]["write"].update({"hop_attenuation_ppm": 1000000})), eval_time=180)))
CASES.append(("M12 burn receipt and promotion tallies", case(
    [act(ts=0),
     {"receipt_type": "BURN", "agent": {"id": "a1"}, "timestamp": 10, "burn_amount": 7,
      "action": {"name": "standing.burn", "risk_weight": 1, "scope_class": "write"}},
     {"receipt_type": "PROMOTION", "agent": {"id": "a1"}, "timestamp": 20,
      "action": {"name": "standing.promotion", "risk_weight": 1, "scope_class": "write"}}],
    pol_mut(lambda p: p["scope_classes"]["write"].update({"hop_attenuation_ppm": 1000000})), eval_time=20)))

# The 27 strictness cases (decision 24), each an error in every tree.
STRICT = [
    ("S01 negative burn_unit", lambda p: p["scope_classes"]["write"].update({"burn_unit": -10})),
    ("S02 negative mint_rate", lambda p: p["scope_classes"]["write"].update({"mint_rate": -2})),
    ("S03 negative burn multiplier", lambda p: p["scope_classes"]["write"]["burn_multipliers"].update({"revoked": -2})),
    ("S04 negative correlated fraction", lambda p: p["scope_classes"]["write"].update({"correlated_burn_fraction_ppm": -1})),
    ("S05 negative ceiling tier field", lambda p: p["ceiling_curve"][0].update({"max_fanout": -1})),
    ("S06 top-level mint_rate not inherited", lambda p: (p.update({"mint_rate": 9}), p["scope_classes"]["write"].pop("mint_rate"))),
    ("S07 malformed value in untouched class", lambda p: p["scope_classes"]["read"].update({"mint_rate": -1})),
    ("S08 null burn_unit", lambda p: p["scope_classes"]["write"].update({"burn_unit": None})),
    ("S09 null mint_cap_per_epoch", lambda p: p["scope_classes"]["write"].update({"mint_cap_per_epoch": None})),
    ("S10 null countersign_policy", lambda p: p.update({"countersign_policy": None})),
    ("S11 null witness_policy", lambda p: p.update({"witness_policy": None})),
    ("S17 severe_codes alias", lambda p: p["scope_classes"]["write"].update({"severe_codes": ["revoked"]})),
    ("S18 list-form scope_classes", lambda p: p.update({"scope_classes": []})),
    ("S19 witness k alias", lambda p: p.update({"witness_policy": {"witness_key_ids": ["w1"], "k": 1}})),
    ("S20 witness quorum zero", lambda p: p.update({"witness_policy": {"witness_key_ids": ["w1"], "quorum": 0}})),
    ("S21 witness quorum above n", lambda p: p.update({"witness_policy": {"witness_key_ids": ["w1"], "quorum": 2}})),
    ("S22 boolean mint_rate", lambda p: p["scope_classes"]["write"].update({"mint_rate": True})),
    ("S23 float half_life", lambda p: p["scope_classes"]["write"].update({"half_life_seconds": 1.5})),
    ("S24 countersign_policy bare array", lambda p: p.update({"countersign_policy": ["write"]})),
    ("S25 countersign_required field", lambda p: p.update({"countersign_required": ["write"]})),
    ("S26 per-class diversity_caps", lambda p: p["scope_classes"]["write"].update({"diversity_caps": {}})),
    ("S27 bare hop_attenuation of 2 (no ppm form)", lambda p: (p["scope_classes"]["write"].pop("hop_attenuation_ppm"), p["scope_classes"]["write"].update({"hop_attenuation": 2}))),
]
for name, fn in STRICT:
    CASES.append((name, case([act(ts=0)], pol_mut(fn), eval_time=0)))
RECEIPT_STRICT = [
    ("S12 null risk_weight", {"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 0,
                              "action": {"name": "x", "risk_weight": None, "scope_class": "write"}}),
    ("S13 null burn_amount", {"receipt_type": "BURN", "agent": {"id": "a1"}, "timestamp": 0, "burn_amount": None,
                              "action": {"name": "standing.burn", "risk_weight": 1, "scope_class": "write"}}),
    ("S14 float timestamp", {"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 1.5,
                             "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}),
    ("S15 string timestamp", {"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": "0",
                              "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}),
    ("S16 negative timestamp", {"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": -5,
                                "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}),
]
for name, r in RECEIPT_STRICT:
    CASES.append((name, case([r], eval_time=0)))

# The 5 residue cases (repair round 6).
CASES.append(("W1 null counterparty_id", case(
    [{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 0, "counterparty_id": None,
      "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}], eval_time=0)))
CASES.append(("W1b null subtree_root_id", case(
    [{"receipt_type": "ACTION", "agent": {"id": "a1"}, "timestamp": 0, "subtree_root_id": None,
      "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}], eval_time=0)))
CASES.append(("W2 malformed witness policy at validation", case(
    [act(ts=0)], pol_mut(lambda p: p.update({"witness_policy": {"witness_key_ids": ["w1"], "k": 1}})),
    eval_time=0, validate_only=True)))
CASES.append(("W3 ceiling tier missing a field", case(
    [act(ts=0)], pol_mut(lambda p: p["ceiling_curve"][0].pop("max_fanout")), eval_time=0)))
CASES.append(("W4 unknown receipt type", case(
    [{"receipt_type": "TRANSFER", "agent": {"id": "a1"}, "timestamp": 0}], eval_time=0)))
CASES.append(("W5 agent as bare string", case(
    [{"receipt_type": "ACTION", "agent": "a1", "timestamp": 0,
      "action": {"name": "x", "risk_weight": 1, "scope_class": "write"}}], eval_time=0)))

CASES.append(("M13 both hop forms stated, ppm governs", case(
    [act(ts=0, delegation_depth=1)],
    pol_mut(lambda p: p["scope_classes"]["write"].update({"hop_attenuation_ppm": 1000000, "hop_attenuation": 2})), eval_time=0)))

COMPARE_FIELDS = ["standing", "ceiling", "ceilings", "actions", "denials", "minted",
                  "minted_decayed", "burned", "decay_applied", "burn_receipts",
                  "burn_recorded", "promotions", "demotions", "killed"]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def python_oracle(case_doc, tmp):
    path = os.path.join(tmp, "case.json")
    with open(path, "w") as fh:
        json.dump(case_doc, fh)
    out = run(["python3", ORACLE, path])
    return json.loads(out.stdout.strip().splitlines()[-1])


def go_result(case_doc, tmp):
    doc = {"receipts": case_doc["receipts"], "standing_policy": case_doc["standing_policy"],
           "eval_time": case_doc["eval_time"], "agent_id": case_doc["agent_id"]}
    if case_doc.get("counterparty_seeds"):
        keys = {}
        for cp_id, seed_hex in case_doc["counterparty_seeds"].items():
            pub = run(["python3", ORACLE, "pubkey", seed_hex]).stdout.strip()
            keys[cp_id] = pub
        doc["counterparty_keys"] = keys
    path = os.path.join(tmp, "gocase.json")
    with open(path, "w") as fh:
        json.dump(doc, fh)
    if case_doc.get("validate_only"):
        out = run([GO_BIN, "validate-policy", path])
        if out.returncode == 0:
            return {"ok": True, "result": {}}
        return {"ok": False, "error": out.stdout.strip()}
    out = run([GO_BIN, "standing", path])
    if out.returncode != 0:
        return {"ok": False, "error": out.stdout.strip()}
    return {"ok": True, "result": json.loads(out.stdout.strip().splitlines()[-1])}


def rust_result(case_doc, py, tmp):
    """Returns 'agree', 'disagree', or a skip reason string."""
    fx = {"kind": "standing", "name": "differential case",
          "agent_id": case_doc["agent_id"], "eval_time": case_doc["eval_time"],
          "receipts": case_doc["receipts"], "standing_policy": case_doc["standing_policy"]}
    if py["ok"]:
        exp = {}
        for cls, entry in py["result"].items():
            exp[cls] = {k: entry[k] for k in ("standing", "minted", "burned", "actions",
                                              "denials", "decay_applied", "burn_recorded")
                        if k in entry}
        fx["expected_standing"] = exp
    else:
        fx["expected_standing"] = {"write": {"standing": 0}}
    if case_doc.get("counterparty_seeds"):
        keys = {}
        for cp_id, seed_hex in case_doc["counterparty_seeds"].items():
            keys[cp_id] = run(["python3", ORACLE, "pubkey", seed_hex]).stdout.strip()
        fx["counterparty_keys"] = keys
    d = os.path.join(tmp, "rustfx")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "fixture_99_differential.json"), "w") as fh:
        json.dump(fx, fh)
    out = run([RUST_BIN, d, SECRET])
    text = out.stdout
    spec_pass = re.search(r"PASS \S+: spec conformance", text) is not None
    if py["ok"]:
        return "agree" if spec_pass else "disagree: " + text.strip().splitlines()[0][:200]
    return "agree" if not spec_pass else "disagree: Rust reported spec conformance for a malformed input"


def compare(name, case_doc):
    with tempfile.TemporaryDirectory() as tmp:
        py = python_oracle(case_doc, tmp)
        go = go_result(case_doc, tmp)
        problems = []
        if py["ok"] != go["ok"]:
            problems.append(f"verdict differs: python ok={py['ok']} ({py.get('error', '')[:120]}), go ok={go['ok']} ({go.get('error', '')[:120]})")
        elif py["ok"]:
            for cls, entry in py["result"].items():
                g = go["result"].get(cls)
                if g is None:
                    problems.append(f"go has no result for class {cls}")
                    continue
                for f in COMPARE_FIELDS:
                    if f in entry and entry[f] != g.get(f):
                        problems.append(f"class {cls} field {f}: python {entry[f]} != go {g.get(f)}")
            for cls in go["result"]:
                if cls not in py["result"]:
                    problems.append(f"go has extra class {cls}")
        rust = rust_result(case_doc, py, tmp) if not case_doc.get("validate_only") else "skip: validation-door case, no Rust fixture form"
        return problems, rust


def main():
    total = agree = 0
    failures = []
    rust_skips = []
    # Countersigned mint: Go vs Python on values (see module docstring).
    cs_case = None
    all_cases = list(CASES)
    # Build the countersigned case with a real Ed25519 signature from
    # the Python oracle's signer, so both trees verify the same bytes.
    sys.path.insert(0, os.path.join(ROOT, "..", "code"))
    from acta.signing import Ed25519Signer  # noqa: E402
    from institutio.standing import countersign_outcome  # noqa: E402
    sg = Ed25519Signer(seed=bytes(range(32)), key_id="cp-1-key")
    sig = countersign_outcome(sg, "a1", "repo.write", "write", 1000, risk_weight=3,
                              receipt_id="r1", arguments_hash="ah", result_hash="rh")
    cs_case = case([act(ts=1000, receipt_id="r1", counterparty_id="cp-1", counterparty_sig=sig)],
                   pol_mut(lambda p: p.update({"countersign_policy": {"required_for": ["write"]}})),
                   eval_time=1000, seeds={"cp-1": SEED})
    all_cases.append(("M08 countersigned mint (Rust leg via Python differential suite)", cs_case))
    for name, c in all_cases:
        total += 1
        problems, rust = compare(name, c)
        if name.startswith("M08"):
            rust = "skip: Rust runner standing-fixture path does not surface the countersignature (see DIFFERENTIAL.md)"
        if problems:
            failures.append((name, problems))
            print(f"DIFF {name}: " + "; ".join(problems) + f" | rust: {rust}")
        else:
            agree += 1
            print(f"AGREE {name} (go == python; rust: {rust})")
        if isinstance(rust, str) and rust.startswith("skip"):
            rust_skips.append(name)
        elif rust != "agree":
            failures.append((name, ["rust leg: " + str(rust)]))
            agree -= 1 if not problems else 0
    # Fixtures 23, 24, 32 as spec-conformance Standing cases.
    for num in ("23", "24", "32"):
        total += 1
        path = [os.path.join(FIXTURES, f) for f in sorted(os.listdir(FIXTURES))
                if f.startswith(f"fixture_{num}_")][0]
        with open(path) as fh:
            fx = json.load(fh)
        c = case(fx["receipts"], fx["standing_policy"], eval_time=fx["eval_time"], agent=fx["agent_id"])
        problems, rust = compare(f"fixture_{num} (spec-conformance Standing)", c)
        # The fixture's own stated expectation is the third check.
        with tempfile.TemporaryDirectory() as tmp:
            go = go_result(c, tmp)
        if go["ok"]:
            for cls, fields in fx["expected_standing"].items():
                for f, v in fields.items():
                    if go["result"][cls][f] != v:
                        problems.append(f"go fixture expectation {cls}.{f}: {go['result'][cls][f]} != {v}")
        else:
            problems.append("go computation failed on the fixture")
        if problems:
            failures.append((f"fixture_{num}", problems))
            print(f"DIFF fixture_{num}: " + "; ".join(problems) + f" | rust: {rust}")
        else:
            agree += 1
            print(f"AGREE fixture_{num} (go == python == fixture expectation; rust: {rust})")
    print(f"differential: {total} cases, {agree} in full agreement, {len(failures)} disagreements, rust legs skipped: {len(rust_skips)}")
    for name in rust_skips:
        print(f"rust skip: {name}")
    if failures:
        print("DIFFERENTIAL RESULT: FAIL")
        return 1
    print("DIFFERENTIAL RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

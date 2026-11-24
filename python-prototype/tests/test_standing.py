"""Tests for ComputeStanding: stub-era shape plus the normative
Section 16 computation. Author: Gavin Blacklock."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import HmacSigner  # noqa: E402
from institutio import (  # noqa: E402
    ComputeStanding,
    build_checkpoint,
    compute_standing,
    countersign_outcome,
    effective_authority,
)

CP_SIGNER = HmacSigner(b"counterparty-secret", key_id="cp-1")
CP_VERIFIERS = {"cp-1": CP_SIGNER}

# Repair round 3 (finding S3): policies in this suite state every
# field Section 16.10 assigns to the policy. CURVE is one generous
# tier; OLD_DEFAULT_CURVE is the tier set the prototype once
# defaulted to, stated explicitly where a test asserts its tiers.
HL = 10000000
CURVE = [{"min_standing": 0, "max_budget_per_action": 1000000,
          "max_budget_per_epoch": 10000000, "max_irreversibility": 3,
          "max_data_sensitivity": 3, "max_delegation_depth": 3,
          "max_fanout": 8}]
OLD_DEFAULT_CURVE = [
    {"min_standing": 0, "max_budget_per_action": 5,
     "max_budget_per_epoch": 25, "max_irreversibility": 0,
     "max_data_sensitivity": 0, "max_delegation_depth": 0,
     "max_fanout": 0},
    {"min_standing": 1, "max_budget_per_action": 10,
     "max_budget_per_epoch": 50, "max_irreversibility": 0,
     "max_data_sensitivity": 1, "max_delegation_depth": 0,
     "max_fanout": 1},
    {"min_standing": 10, "max_budget_per_action": 50,
     "max_budget_per_epoch": 250, "max_irreversibility": 1,
     "max_data_sensitivity": 2, "max_delegation_depth": 1,
     "max_fanout": 2},
    {"min_standing": 50, "max_budget_per_action": 250,
     "max_budget_per_epoch": 1000, "max_irreversibility": 2,
     "max_data_sensitivity": 3, "max_delegation_depth": 2,
     "max_fanout": 4},
    {"min_standing": 200, "max_budget_per_action": 1000,
     "max_budget_per_epoch": 5000, "max_irreversibility": 3,
     "max_data_sensitivity": 3, "max_delegation_depth": 3,
     "max_fanout": 8},
]


def receipt(kind, timestamp, scope_class="default"):
    return {
        "receipt_type": kind,
        "timestamp": timestamp,
        "action": {"name": "tool.call", "scope_class": scope_class},
    }


class TestStandingStub(unittest.TestCase):
    def test_actions_mint_and_denials_burn(self):
        # Stated completely (finding S3): mint_rate 1, burn_unit 5
        # with a multiplier of 1 for the denial's reason code.
        policy = {"scope_classes": {"default": {
            "mint_rate": 1, "half_life_seconds": HL,
            "burn_unit": 5, "burn_multipliers": {"budget": 1},
            "ceiling_curve": CURVE}}}
        denial = receipt("DENIAL", 120)
        denial["reason_code"] = "budget"
        receipts = [receipt("ACTION", 100), receipt("ACTION", 110),
                    denial]
        result = compute_standing(receipts, policy)
        entry = result["default"]
        self.assertEqual(entry["actions"], 2)
        self.assertEqual(entry["denials"], 1)
        self.assertEqual(entry["standing"], 0)  # 2 minted, 5 burned, floor 0

    def test_no_history_means_zero_standing(self):
        self.assertEqual(compute_standing([]), {})

    def test_deterministic(self):
        policy = {"scope_classes": {"default": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        receipts = [receipt("ACTION", 100), receipt("ACTION", 200)]
        self.assertEqual(compute_standing(receipts, policy),
                         compute_standing(list(receipts), policy))

    def test_decay_by_whole_half_lives(self):
        policy = {"scope_classes": {"default": {
            "mint_rate": 8, "half_life_seconds": 100,
            "ceiling_curve": CURVE}}}
        receipts = [receipt("ACTION", 0)]
        result = compute_standing(receipts, policy, eval_time=250)
        self.assertEqual(result["default"]["standing"], 2)  # 8 >> 2

    def test_alias_is_same_function(self):
        self.assertIs(ComputeStanding, compute_standing)

    def test_per_scope_class_separation(self):
        policy = {"scope_classes": {
            name: {"mint_rate": 1, "half_life_seconds": HL,
                   "ceiling_curve": CURVE}
            for name in ("code", "funds")}}
        receipts = [receipt("ACTION", 100, "code"),
                    receipt("ACTION", 100, "funds")]
        result = compute_standing(receipts, policy)
        self.assertEqual(sorted(result), ["code", "funds"])


def rich_receipt(kind, timestamp, scope_class="write", risk_weight=1,
                 counterparty_sig=None, counterparty_id="cp-1",
                 reason_code=None, agent_id="agent-1", depth=0,
                 burn_amount=None):
    action = {"name": "tool.call", "scope_class": scope_class,
              "risk_weight": risk_weight, "delegation_depth": depth}
    receipt = {"receipt_type": kind, "timestamp": timestamp,
               "agent": {"id": agent_id}, "action": action}
    if counterparty_sig is not None:
        receipt["counterparty_sig"] = counterparty_sig
        receipt["counterparty_id"] = counterparty_id
    if reason_code is not None:
        receipt["reason_code"] = reason_code
    if burn_amount is not None:
        receipt["burn_amount"] = burn_amount
    return receipt


class TestStandingNormative(unittest.TestCase):
    def test_countersigned_mint_is_risk_weighted(self):
        policy = {"countersign_policy": {"required_for": ["write"]},
                  "scope_classes": {"write": {
                      "mint_rate": 2, "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        sig = countersign_outcome(CP_SIGNER, "agent-1", "tool.call",
                                  "write", 100, risk_weight=3)
        receipts = [rich_receipt("ACTION", 100, risk_weight=3,
                                 counterparty_sig=sig)]
        result = compute_standing(receipts, policy, eval_time=100,
                                  counterparty_verifiers=CP_VERIFIERS)
        self.assertEqual(result["write"]["standing"], 6)
        self.assertEqual(result["write"]["minted"], 6)

    def test_uncountersigned_mint_is_zero_where_required(self):
        policy = {"countersign_policy": {"required_for": ["write"]},
                  "scope_classes": {"write": {
                      "mint_rate": 2, "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 100, risk_weight=3)]
        result = compute_standing(receipts, policy, eval_time=100)
        self.assertEqual(result["write"]["standing"], 0)
        self.assertEqual(result["write"]["minted"], 0)
        self.assertEqual(result["write"]["actions"], 1)

    def test_mint_cap_per_epoch_binds(self):
        policy = {"epoch_seconds": 100,
                  "scope_classes": {"write": {
                      "mint_rate": 10, "mint_cap_per_epoch": 25,
                      "half_life_seconds": HL,
                      "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10), rich_receipt("ACTION", 20),
                    rich_receipt("ACTION", 30), rich_receipt("ACTION", 110)]
        result = compute_standing(receipts, policy, eval_time=110)
        # 25 in epoch 0 (cap), 10 in epoch 1.
        self.assertEqual(result["write"]["minted"], 35)

    def test_diversity_cap_per_counterparty(self):
        # The cap is stated in the Section 16.10 decision 8 form
        # (the diversity_caps object at policy level); the flat
        # prototype key this test once used is retired (repair
        # round 4, observation o3). Same cap, same expectation.
        policy = {"diversity_caps": {"per_counterparty_per_epoch": 15},
                  "scope_classes": {"write": {
            "mint_rate": 10,
            "half_life_seconds": HL, "ceiling_curve": CURVE}}}
        receipts = [
            rich_receipt("ACTION", 10, counterparty_id="cp-1",
                         counterparty_sig="s1"),
            rich_receipt("ACTION", 20, counterparty_id="cp-1",
                         counterparty_sig="s2"),
            rich_receipt("ACTION", 30, counterparty_id="cp-2",
                         counterparty_sig="s3"),
        ]
        result = compute_standing(receipts, policy, eval_time=30)
        self.assertEqual(result["write"]["minted"], 25)  # 15 + 0 + 10

    def test_severe_denial_erases_an_epoch_of_mint(self):
        # Section 16.10 decision 2: the I5 floor is carried by the
        # policy. burn_unit 36 with multiplier 1 burns the whole
        # 36-unit epoch at the first severe denial, by the closed
        # form alone, with no computation-time floor.
        policy = {"scope_classes": {"write": {
            "mint_rate": 6, "mint_cap_per_epoch": 36,
            "burn_unit": 36, "burn_multipliers": {"revoked": 1},
            "half_life_seconds": HL, "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10 + i) for i in range(6)]
        receipts.append(rich_receipt("DENIAL", 100, reason_code="revoked"))
        result = compute_standing(receipts, policy, eval_time=100)
        self.assertEqual(result["write"]["minted"], 36)
        self.assertEqual(result["write"]["burned"], 36)
        self.assertEqual(result["write"]["standing"], 0)

    def test_burn_is_super_linear_in_denial_count(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 100, "half_life_seconds": HL,
            "burn_unit": 5, "burn_multipliers": {"budget": 1},
            "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10)]
        receipts.append(rich_receipt("DENIAL", 20, reason_code="budget"))
        receipts.append(rich_receipt("DENIAL", 30, reason_code="budget"))
        result = compute_standing(receipts, policy, eval_time=30)
        # Section 16.10 decision 2 closed form: burns 5 * 1 * 1^2
        # then 5 * 1 * 2^2, total 25 against 100 minted.
        self.assertEqual(result["write"]["burned"], 25)
        self.assertEqual(result["write"]["standing"], 75)

    def test_burn_receipt_records_without_double_burning(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 100, "half_life_seconds": HL,
            "burn_unit": 5, "burn_multipliers": {"budget": 1},
            "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10),
                    rich_receipt("DENIAL", 20, reason_code="budget"),
                    rich_receipt("BURN", 21, burn_amount=5)]
        result = compute_standing(receipts, policy, eval_time=21)
        self.assertEqual(result["write"]["burned"], 5)
        self.assertEqual(result["write"]["burn_recorded"], 5)
        self.assertEqual(result["write"]["standing"], 95)

    def test_promotion_and_demotion_confer_nothing(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10),
                    rich_receipt("PROMOTION", 20),
                    rich_receipt("DEMOTION", 30)]
        result = compute_standing(receipts, policy, eval_time=30)
        self.assertEqual(result["write"]["standing"], 1)
        self.assertEqual(result["write"]["promotions"], 1)
        self.assertEqual(result["write"]["demotions"], 1)

    def test_hop_attenuation(self):
        # Stated as hop_attenuation_ppm (decision 6); the retired
        # hop_attenuation_percent alias this test once used was
        # the same 50 percent (repair round 4, observation o3).
        policy = {"scope_classes": {"write": {
                      "mint_rate": 8, "half_life_seconds": HL,
                      "hop_attenuation_ppm": 500000,
                      "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10, depth=2)]
        result = compute_standing(receipts, policy, eval_time=10)
        self.assertEqual(result["write"]["minted"], 2)  # 8 * 1/4

    def test_kill_burn_zeroes_and_blocks_later_mint(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10),
                    rich_receipt("ACTION", 20),
                    rich_receipt("KILL-BURN", 30),
                    rich_receipt("ACTION", 40)]
        result = compute_standing(receipts, policy, eval_time=40,
                                  agent_id="agent-1")
        self.assertEqual(result["write"]["standing"], 0)
        self.assertTrue(result["write"]["killed"])

    def test_new_agent_starts_at_zero(self):
        receipts = [rich_receipt("ACTION", 10, agent_id="agent-1")]
        self.assertEqual(
            compute_standing(receipts, None, eval_time=10,
                             agent_id="agent-copy"), {})

    def test_ceiling_curve_tiers(self):
        # The tier set this test asserts is stated in the policy
        # (finding S3); it was once the prototype's default curve.
        policy = {"scope_classes": {"write": {
            "mint_rate": 10, "half_life_seconds": HL,
            "ceiling_curve": OLD_DEFAULT_CURVE}}}
        receipts = [rich_receipt("ACTION", 10 + i) for i in range(6)]
        entry = compute_standing(receipts, policy, eval_time=20)["write"]
        self.assertEqual(entry["standing"], 60)
        self.assertEqual(entry["ceilings"]["max_irreversibility"], 2)
        self.assertEqual(entry["ceilings"]["max_budget_per_action"], 250)

    def test_effective_authority_is_the_minimum(self):
        eff = effective_authority(
            {"spend_units": 1000, "external_calls": 50},
            {"spend_units": 100},
            {"spend_units": 25, "max_fanout": 2},
        )
        self.assertEqual(eff["spend_units"], 25)
        self.assertEqual(eff["external_calls"], 50)
        self.assertEqual(eff["max_fanout"], 2)

    def test_checkpoint_is_stable_for_an_untouched_sibling(self):
        policy = {"scope_classes": {"write": {
            "mint_rate": 1, "half_life_seconds": HL,
            "burn_unit": 5, "burn_multipliers": {"revoked": 1},
            "ceiling_curve": CURVE}}}
        receipts = [rich_receipt("ACTION", 10, agent_id="rogue"),
                    rich_receipt("ACTION", 20, agent_id="sibling"),
                    rich_receipt("KILL-BURN", 30, agent_id="rogue"),
                    rich_receipt("DENIAL", 40, agent_id="rogue",
                                 reason_code="revoked")]
        before = build_checkpoint(receipts[:2], policy, eval_time=20,
                                  agent_id="sibling")
        after = build_checkpoint(receipts, policy, eval_time=40,
                                 agent_id="sibling")
        self.assertEqual(before["standing_vector"],
                         after["standing_vector"])
        rogue = build_checkpoint(receipts, policy, eval_time=40,
                                 agent_id="rogue")
        self.assertEqual(rogue["standing_vector"]["write"], 0)
        self.assertEqual(rogue["denials_by_reason_code"],
                         {"revoked": 1})


if __name__ == "__main__":
    unittest.main()

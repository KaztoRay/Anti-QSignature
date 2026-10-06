import unittest
from pathlib import Path


class QuantumHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from qdk import qsharp
        except ImportError as exc:
            raise unittest.SkipTest("QDK is not installed") from exc
        cls.qsharp = qsharp
        project = Path(__file__).resolve().parents[1] / "quantum"
        qsharp.init(project_root=str(project))

    def test_hardened_policy_rejects_all_bounded_counterexamples(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunPolicyInvariantHarness()"
        )
        self.assertEqual(checked, 128)
        self.assertGreater(accepted, 0)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_grover_harness_amplifies_known_mutant_counterexample(self) -> None:
        shots = self.qsharp.run("AntiQSignature.RunWalletAttackHarness(9)", shots=8)
        target = "[One, Zero, Zero, Zero, Zero, One, Zero]"
        hits = sum(1 for shot in shots if str(shot) == target)
        self.assertGreaterEqual(hits, 6)

    def test_upgrade_harness_rejects_mutated_authorization(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunUpgradeInvariantHarness()"
        )
        self.assertEqual(checked, 256)
        self.assertEqual(accepted, 1)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_signature_domain_harness_blocks_cross_context_replay(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunSignatureDomainHarness()"
        )
        self.assertEqual(checked, 64)
        self.assertEqual(accepted, 1)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_entropy_harness_models_grover_security_margin(self) -> None:
        classical, quantum = self.qsharp.eval("AntiQSignature.RunEntropySecurityHarness()")
        self.assertEqual(classical, [128, 192, 256, 384, 512])
        self.assertEqual(quantum, [64, 96, 128, 192, 256])

    def test_contract_risk_harness_requires_hybrid_for_raw_ecdsa(self) -> None:
        score, sensitive, mode, triggered = self.qsharp.eval(
            "AntiQSignature.RunContractRiskHarness(8)"
        )
        self.assertEqual(score, 12)
        self.assertEqual(sensitive, 1)
        self.assertEqual(mode, 1)
        self.assertEqual(triggered, 1)

    def test_transaction_sequence_harness_blocks_replay_and_freeze_bypass(self) -> None:
        checked, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunTransactionSequenceHarness()"
        )
        self.assertEqual(checked, 64)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_account_abstraction_harness_binds_entrypoint_and_hybrid_signatures(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunAccountAbstractionHarness()"
        )
        self.assertEqual(checked, 256)
        self.assertEqual(accepted, 1)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_key_rotation_harness_requires_current_hybrid_auth_and_epoch_advance(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunKeyRotationHarness()"
        )
        self.assertEqual(checked, 256)
        self.assertEqual(accepted, 1)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_guardian_recovery_harness_requires_threshold_and_replay_protection(self) -> None:
        checked, accepted, hardened_violations, mutant_violations = self.qsharp.eval(
            "AntiQSignature.RunGuardianRecoveryHarness()"
        )
        self.assertEqual(checked, 256)
        self.assertEqual(accepted, 4)
        self.assertEqual(hardened_violations, 0)
        self.assertGreater(mutant_violations, 0)

    def test_dynamic_grover_harness_amplifies_scanner_risk_mask(self) -> None:
        target_mask = 0b10100101
        shots = self.qsharp.run(
            f"AntiQSignature.RunDynamicRiskGrover(8, {target_mask}, 13)", shots=8
        )
        target = "[One, Zero, One, Zero, Zero, One, Zero, One]"
        hits = sum(1 for shot in shots if str(shot) == target)
        self.assertGreaterEqual(hits, 6)


if __name__ == "__main__":
    unittest.main()

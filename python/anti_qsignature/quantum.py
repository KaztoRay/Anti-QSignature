from __future__ import annotations

import math
import time
import warnings
from pathlib import Path
from typing import Any


def _analytical_summary(search_bits: int, policy_variables: int) -> dict[str, Any]:
    return {
        "search_bits": search_bits,
        "classical_search_steps": f"2^{search_bits}",
        "grover_search_steps": f"~2^{search_bits // 2}",
        "grover_iterations_log2": round(search_bits / 2, 2),
        "policy_variables": policy_variables,
        "policy_state_space": 2**policy_variables,
        "recommended_symmetric_bits": 256,
        "note": "Analytical values are security-scale estimates, not a hardware execution forecast.",
    }


def run_quantum_analysis(
    project_root: Path,
    search_bits: int = 256,
    policy_variables: int = 7,
    mode: str = "auto",
    finding_rule_ids: set[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = _analytical_summary(search_bits, policy_variables)
    if mode == "off":
        result.update({"qsharp_status": "disabled"})
        return result
    try:
        from qdk import qsharp

        started = time.perf_counter()
        qsharp.init(project_root=str(project_root / "quantum"))
        states_checked, accepted, hardened_violations, mutant_violations = qsharp.eval(
            "AntiQSignature.RunPolicyInvariantHarness()"
        )
        upgrade_checked, upgrade_accepted, upgrade_hardened, upgrade_mutant = qsharp.eval(
            "AntiQSignature.RunUpgradeInvariantHarness()"
        )
        domain_checked, domain_accepted, domain_hardened, domain_mutant = qsharp.eval(
            "AntiQSignature.RunSignatureDomainHarness()"
        )
        classical_bits, quantum_bits = qsharp.eval(
            "AntiQSignature.RunEntropySecurityHarness()"
        )
        sequence_checked, sequence_hardened, sequence_mutant = qsharp.eval(
            "AntiQSignature.RunTransactionSequenceHarness()"
        )
        aa_checked, aa_accepted, aa_hardened, aa_mutant = qsharp.eval(
            "AntiQSignature.RunAccountAbstractionHarness()"
        )
        feature_rules = ["AQ001", "AQ002", "AQ003", "AQ007", "AQ008", "AQ009", "AQ015", "AQ011"]
        active_rules = finding_rule_ids or set()
        feature_mask = sum(1 << index for index, rule in enumerate(feature_rules) if rule in active_rules)
        contract_score, sensitive_count, required_mode, triggered = qsharp.eval(
            f"AntiQSignature.RunContractRiskHarness({feature_mask})"
        )
        harnesses_valid = (
            hardened_violations == 0
            and mutant_violations > 0
            and upgrade_hardened == 0
            and upgrade_mutant > 0
            and domain_hardened == 0
            and domain_mutant > 0
            and sequence_hardened == 0
            and sequence_mutant > 0
            and aa_hardened == 0
            and aa_mutant > 0
        )
        if not harnesses_valid:
            raise RuntimeError(
                "Q# differential harness failed to distinguish one or more hardened and mutant policies"
            )

        iterations = max(1, round(math.pi / 4 * math.sqrt(2**policy_variables)))
        expression = f"AntiQSignature.RunWalletAttackHarness({iterations})"
        shots = qsharp.run(expression, shots=32)
        target = "[One, Zero, Zero, Zero, Zero, One, Zero]"
        marked_hits = sum(1 for shot in shots if str(shot) == target)

        resource_estimates: list[dict[str, Any]] = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for register_size in (7, 12, 16):
                estimate = qsharp.estimate(
                    f"AntiQSignature.EstimateAttackRound({register_size})"
                ).data()
                formatted = estimate.get("physicalCountsFormatted", {})
                resource_estimates.append(
                    {
                        "register_qubits": register_size,
                        "runtime": formatted.get("runtime"),
                        "physical_qubits": formatted.get("physicalQubits"),
                        "algorithmic_logical_qubits": formatted.get("algorithmicLogicalQubits"),
                        "algorithmic_logical_depth": formatted.get("algorithmicLogicalDepth"),
                        "t_states": formatted.get("numTstates"),
                    }
                )
        result.update(
            {
                "qsharp_status": "executed",
                "duration_ms": round((time.perf_counter() - started) * 1000),
                "policy_invariant_harness": {
                    "states_checked": states_checked,
                    "hardened_accepted_states": accepted,
                    "hardened_violations": hardened_violations,
                    "mutant_violations_detected": mutant_violations,
                    "differential_validation": "passed",
                },
                "upgrade_invariant_harness": {
                    "states_checked": upgrade_checked,
                    "hardened_accepted_states": upgrade_accepted,
                    "hardened_violations": upgrade_hardened,
                    "mutant_violations_detected": upgrade_mutant,
                    "differential_validation": "passed",
                },
                "signature_domain_harness": {
                    "states_checked": domain_checked,
                    "hardened_accepted_states": domain_accepted,
                    "hardened_violations": domain_hardened,
                    "mutant_violations_detected": domain_mutant,
                    "differential_validation": "passed",
                },
                "entropy_security_harness": [
                    {"classical_bits": classical, "grover_security_bits": quantum}
                    for classical, quantum in zip(classical_bits, quantum_bits)
                ],
                "contract_risk_harness": {
                    "feature_mask": feature_mask,
                    "triggered_features": triggered,
                    "quantum_sensitive_features": sensitive_count,
                    "qsharp_risk_score": contract_score,
                    "required_auth_mode": ["CLASSICAL_ALLOWED", "HYBRID_REQUIRED", "BLOCK_OR_REVIEW"][required_mode],
                },
                "transaction_sequence_harness": {
                    "sequences_checked": sequence_checked,
                    "hardened_violations": sequence_hardened,
                    "mutant_violations_detected": sequence_mutant,
                    "differential_validation": "passed",
                },
                "account_abstraction_harness": {
                    "states_checked": aa_checked,
                    "hardened_accepted_states": aa_accepted,
                    "hardened_violations": aa_hardened,
                    "mutant_violations_detected": aa_mutant,
                    "differential_validation": "passed",
                },
                "total_qsharp_states_verified": states_checked + upgrade_checked + domain_checked + sequence_checked + aa_checked,
                "grover_attack_harness": {
                    "expression": expression,
                    "shots": 32,
                    "target_state_hits": marked_hits,
                    "hit_rate": round(marked_hits / 32, 4),
                    "target_state": "owner + replayable nonce; PQ/code/guardian checks bypassed",
                },
                "attack_round_resource_estimates": resource_estimates,
                "resource_estimate_scope": "Q# policy attack rounds; not a secp256k1 Shor estimate",
            }
        )
    except Exception as exc:
        result.update({"qsharp_status": "unavailable", "qsharp_error": str(exc)[:1000]})
        if mode == "required":
            raise RuntimeError(f"Q# execution was required but failed: {exc}") from exc
    return result

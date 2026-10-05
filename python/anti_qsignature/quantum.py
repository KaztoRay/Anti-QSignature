from __future__ import annotations

import math
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
    project_root: Path, search_bits: int = 256, policy_variables: int = 7, mode: str = "auto"
) -> dict[str, Any]:
    result: dict[str, Any] = _analytical_summary(search_bits, policy_variables)
    if mode == "off":
        result.update({"qsharp_status": "disabled"})
        return result
    try:
        from qdk import qsharp

        qsharp.init(project_root=str(project_root / "quantum"))
        sample_bits = min(max(policy_variables, 2), 8)
        iterations = max(1, round(math.pi / 4 * math.sqrt(2**sample_bits)))
        expression = f"AntiQSignature.RunGroverProbe({sample_bits}, {iterations})"
        shots = qsharp.run(expression, shots=16)
        marked_hits = sum(1 for shot in shots if "One" in str(shot))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            estimate = qsharp.estimate(expression).data()
        formatted = estimate.get("physicalCountsFormatted", {})
        result.update(
            {
                "qsharp_status": "executed",
                "qsharp_expression": expression,
                "shots": 16,
                "marked_state_hits": marked_hits,
                "simulated_qubits": sample_bits,
                "probe_resource_estimate": {
                    "runtime": formatted.get("runtime"),
                    "physical_qubits": formatted.get("physicalQubits"),
                    "algorithmic_logical_qubits": formatted.get("algorithmicLogicalQubits"),
                    "algorithmic_logical_depth": formatted.get("algorithmicLogicalDepth"),
                    "t_states": formatted.get("numTstates"),
                    "scope": "small policy probe only; do not extrapolate this directly to secp256k1",
                },
            }
        )
    except Exception as exc:
        result.update({"qsharp_status": "unavailable", "qsharp_error": str(exc)[:1000]})
        if mode == "required":
            raise RuntimeError(f"Q# execution was required but failed: {exc}") from exc
    return result

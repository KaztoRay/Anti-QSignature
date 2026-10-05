from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FuzzInput:
    caller_is_owner: bool
    pq_signature_valid: bool
    guardian_approved: bool
    frozen: bool
    code_hash_approved: bool
    nonce: int
    expected_nonce: int
    amount: int
    daily_spent: int
    daily_limit: int


def reference_policy(case: FuzzInput) -> bool:
    if case.frozen or not case.code_hash_approved:
        return False
    if not case.caller_is_owner or case.nonce != case.expected_nonce:
        return False
    if case.daily_spent + case.amount > case.daily_limit:
        return case.pq_signature_valid and case.guardian_approved
    return case.pq_signature_valid


def violated_invariants(case: FuzzInput, accepted: bool) -> list[str]:
    failures: list[str] = []
    if accepted and not case.caller_is_owner:
        failures.append("unauthorized-caller")
    if accepted and case.nonce != case.expected_nonce:
        failures.append("nonce-replay-or-gap")
    if accepted and (case.frozen or not case.code_hash_approved):
        failures.append("freeze-or-code-integrity-bypass")
    if accepted and not case.pq_signature_valid:
        failures.append("missing-pq-authorization")
    if accepted and case.daily_spent + case.amount > case.daily_limit and not case.guardian_approved:
        failures.append("high-value-guardian-bypass")
    return failures


def run_policy_fuzz(cases: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    failures: list[dict[str, Any]] = []
    accepted = 0
    for index in range(cases):
        daily_limit = rng.randint(1, 10**6)
        expected_nonce = rng.randint(0, 20)
        supplied_nonce = expected_nonce if rng.random() < 0.5 else rng.randint(0, 20)
        case = FuzzInput(
            caller_is_owner=rng.choice([True, False]),
            pq_signature_valid=rng.choice([True, False]),
            guardian_approved=rng.choice([True, False]),
            frozen=rng.random() < 0.1,
            code_hash_approved=rng.random() >= 0.1,
            nonce=supplied_nonce,
            expected_nonce=expected_nonce,
            amount=rng.randint(0, daily_limit * 2),
            daily_spent=rng.randint(0, daily_limit),
            daily_limit=daily_limit,
        )
        decision = reference_policy(case)
        accepted += int(decision)
        violations = violated_invariants(case, decision)
        if violations and len(failures) < 20:
            failures.append(
                {"case": index, "violations": violations, "input": asdict(case)}
            )
    return {
        "engine": "antiq-reference-policy-fuzzer",
        "seed": seed,
        "cases": cases,
        "accepted": accepted,
        "rejected": cases - accepted,
        "invariant_failures": len(failures),
        "counterexamples": failures,
    }

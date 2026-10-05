namespace AntiQSignature {
    /// Seven-bit bounded wallet model:
    /// 0 owner, 1 PQ signature, 2 guardian, 3 frozen,
    /// 4 approved code hash, 5 correct nonce, 6 high value.
    function IsStateBitSet(state : Int, index : Int) : Bool {
        return (state &&& (1 <<< index)) != 0;
    }

    function HardenedWalletPolicy(state : Int) : Bool {
        let owner = IsStateBitSet(state, 0);
        let pqSignature = IsStateBitSet(state, 1);
        let guardian = IsStateBitSet(state, 2);
        let frozen = IsStateBitSet(state, 3);
        let approvedCode = IsStateBitSet(state, 4);
        let correctNonce = IsStateBitSet(state, 5);
        let highValue = IsStateBitSet(state, 6);
        return owner
            and pqSignature
            and not frozen
            and approvedCode
            and correctNonce
            and (not highValue or guardian);
    }

    /// Deliberately weakened mutation: PQ proof, code hash and guardian checks
    /// are omitted. The harness must find counterexamples for this policy.
    function MutantWalletPolicy(state : Int) : Bool {
        let owner = IsStateBitSet(state, 0);
        let frozen = IsStateBitSet(state, 3);
        let correctNonce = IsStateBitSet(state, 5);
        return owner and not frozen and correctNonce;
    }

    function SecurityInvariantViolated(state : Int, accepted : Bool) : Bool {
        if not accepted {
            return false;
        }
        let owner = IsStateBitSet(state, 0);
        let pqSignature = IsStateBitSet(state, 1);
        let guardian = IsStateBitSet(state, 2);
        let frozen = IsStateBitSet(state, 3);
        let approvedCode = IsStateBitSet(state, 4);
        let correctNonce = IsStateBitSet(state, 5);
        let highValue = IsStateBitSet(state, 6);
        return not owner
            or not pqSignature
            or frozen
            or not approvedCode
            or not correctNonce
            or (highValue and not guardian);
    }

    operation RunPolicyInvariantHarness() : (Int, Int, Int, Int) {
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        mutable hardenedAccepted = 0;
        for state in 0..127 {
            let hardened = HardenedWalletPolicy(state);
            let mutant = MutantWalletPolicy(state);
            if hardened {
                set hardenedAccepted += 1;
            }
            if SecurityInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if SecurityInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (128, hardenedAccepted, hardenedViolations, mutantViolations);
    }
}


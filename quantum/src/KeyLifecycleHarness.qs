namespace AntiQSignature {
    /// Eight-bit post-quantum key rotation model:
    /// 0 EntryPoint caller, 1 classical signature, 2 current PQ signature,
    /// 3 nonzero replacement key, 4 account self-call, 5 nonce binding,
    /// 6 code epoch binding, 7 key epoch increment.
    function HardenedKeyRotation(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 1)
            and IsStateBitSet(state, 2)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 4)
            and IsStateBitSet(state, 5)
            and IsStateBitSet(state, 6)
            and IsStateBitSet(state, 7);
    }

    /// Mutation representing a rotation path that authenticates only ECDSA and
    /// does not bind the self-call or advance the key generation.
    function MutantKeyRotation(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 1)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 5)
            and IsStateBitSet(state, 6);
    }

    function KeyRotationInvariantViolated(state : Int, accepted : Bool) : Bool {
        return accepted and not HardenedKeyRotation(state);
    }

    operation RunKeyRotationHarness() : (Int, Int, Int, Int) {
        mutable hardenedAccepted = 0;
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        for state in 0..255 {
            let hardened = HardenedKeyRotation(state);
            let mutant = MutantKeyRotation(state);
            if hardened {
                set hardenedAccepted += 1;
            }
            if KeyRotationInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if KeyRotationInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (256, hardenedAccepted, hardenedViolations, mutantViolations);
    }

    /// Guardian recovery model:
    /// 0..2 guardian approvals, 3 timelock elapsed, 4 replacement key valid,
    /// 5 code hash approved, 6 policy epoch bound, 7 recovery nonce consumed.
    function HardenedGuardianRecovery(state : Int) : Bool {
        mutable guardianApprovals = 0;
        for index in 0..2 {
            if IsStateBitSet(state, index) {
                set guardianApprovals += 1;
            }
        }
        return guardianApprovals >= 2
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 4)
            and IsStateBitSet(state, 5)
            and IsStateBitSet(state, 6)
            and IsStateBitSet(state, 7);
    }

    function MutantGuardianRecovery(state : Int) : Bool {
        let anyGuardian = IsStateBitSet(state, 0)
            or IsStateBitSet(state, 1)
            or IsStateBitSet(state, 2);
        return anyGuardian and IsStateBitSet(state, 4);
    }

    function GuardianRecoveryInvariantViolated(state : Int, accepted : Bool) : Bool {
        return accepted and not HardenedGuardianRecovery(state);
    }

    operation RunGuardianRecoveryHarness() : (Int, Int, Int, Int) {
        mutable hardenedAccepted = 0;
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        for state in 0..255 {
            let hardened = HardenedGuardianRecovery(state);
            let mutant = MutantGuardianRecovery(state);
            if hardened {
                set hardenedAccepted += 1;
            }
            if GuardianRecoveryInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if GuardianRecoveryInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (256, hardenedAccepted, hardenedViolations, mutantViolations);
    }
}

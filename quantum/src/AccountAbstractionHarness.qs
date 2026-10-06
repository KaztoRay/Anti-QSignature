namespace AntiQSignature {
    /// Eight-bit ERC-4337 validation model:
    /// 0 EntryPoint caller, 1 sender/account match, 2 chain bound,
    /// 3 nonce bound, 4 code epoch bound, 5 policy epoch bound,
    /// 6 classical signature, 7 PQ signature.
    function Hardened4337Validation(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 1)
            and IsStateBitSet(state, 2)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 4)
            and IsStateBitSet(state, 5)
            and IsStateBitSet(state, 6)
            and IsStateBitSet(state, 7);
    }

    /// Mutation representing a conventional account that only checks ECDSA.
    function Mutant4337Validation(state : Int) : Bool {
        return IsStateBitSet(state, 1)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 6);
    }

    function AccountAbstractionInvariantViolated(state : Int, accepted : Bool) : Bool {
        if not accepted {
            return false;
        }
        return not IsStateBitSet(state, 0)
            or not IsStateBitSet(state, 1)
            or not IsStateBitSet(state, 2)
            or not IsStateBitSet(state, 3)
            or not IsStateBitSet(state, 4)
            or not IsStateBitSet(state, 5)
            or not IsStateBitSet(state, 6)
            or not IsStateBitSet(state, 7);
    }

    operation RunAccountAbstractionHarness() : (Int, Int, Int, Int) {
        mutable hardenedAccepted = 0;
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        for state in 0..255 {
            let hardened = Hardened4337Validation(state);
            let mutant = Mutant4337Validation(state);
            if hardened {
                set hardenedAccepted += 1;
            }
            if AccountAbstractionInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if AccountAbstractionInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (256, hardenedAccepted, hardenedViolations, mutantViolations);
    }
}

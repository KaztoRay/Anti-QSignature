namespace AntiQSignature {
    /// Eight-bit upgrade model:
    /// 0 admin, 1 PQ signature, 2 guardian, 3 timelock,
    /// 4 code hash, 5 manifest, 6 epoch increased, 7 emergency frozen.
    function HardenedUpgradePolicy(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 1)
            and IsStateBitSet(state, 2)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 4)
            and IsStateBitSet(state, 5)
            and IsStateBitSet(state, 6)
            and not IsStateBitSet(state, 7);
    }

    function MutantUpgradePolicy(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 6)
            and not IsStateBitSet(state, 7);
    }

    function UpgradeInvariantViolated(state : Int, accepted : Bool) : Bool {
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
            or IsStateBitSet(state, 7);
    }

    operation RunUpgradeInvariantHarness() : (Int, Int, Int, Int) {
        mutable accepted = 0;
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        for state in 0..255 {
            let hardened = HardenedUpgradePolicy(state);
            let mutant = MutantUpgradePolicy(state);
            if hardened {
                set accepted += 1;
            }
            if UpgradeInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if UpgradeInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (256, accepted, hardenedViolations, mutantViolations);
    }

    /// Six signature-domain bindings:
    /// chainId, wallet, EntryPoint, nonce, code epoch and policy epoch.
    function HardenedDomainPolicy(state : Int) : Bool {
        return IsStateBitSet(state, 0)
            and IsStateBitSet(state, 1)
            and IsStateBitSet(state, 2)
            and IsStateBitSet(state, 3)
            and IsStateBitSet(state, 4)
            and IsStateBitSet(state, 5);
    }

    function MutantDomainPolicy(state : Int) : Bool {
        return IsStateBitSet(state, 3);
    }

    function DomainInvariantViolated(state : Int, accepted : Bool) : Bool {
        if not accepted {
            return false;
        }
        return not IsStateBitSet(state, 0)
            or not IsStateBitSet(state, 1)
            or not IsStateBitSet(state, 2)
            or not IsStateBitSet(state, 3)
            or not IsStateBitSet(state, 4)
            or not IsStateBitSet(state, 5);
    }

    operation RunSignatureDomainHarness() : (Int, Int, Int, Int) {
        mutable accepted = 0;
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;
        for state in 0..63 {
            let hardened = HardenedDomainPolicy(state);
            let mutant = MutantDomainPolicy(state);
            if hardened {
                set accepted += 1;
            }
            if DomainInvariantViolated(state, hardened) {
                set hardenedViolations += 1;
            }
            if DomainInvariantViolated(state, mutant) {
                set mutantViolations += 1;
            }
        }
        return (64, accepted, hardenedViolations, mutantViolations);
    }

    operation RunEntropySecurityHarness() : (Int[], Int[]) {
        let classicalSecurityBits = [128, 192, 256, 384, 512];
        mutable quantumSecurityBits = [];
        for bits in classicalSecurityBits {
            set quantumSecurityBits += [bits / 2];
        }
        return (classicalSecurityBits, quantumSecurityBits);
    }
}

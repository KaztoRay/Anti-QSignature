namespace AntiQSignature {
    /// Feature mask from the selected contract project:
    /// 0 tx.origin, 1 delegatecall, 2 selfdestruct, 3 raw ECDSA,
    /// 4 low-entropy commitment, 5 upgrade surface,
    /// 6 oversized bytecode, 7 block-derived randomness.
    operation RunContractRiskHarness(featureMask : Int) : (Int, Int, Int, Int) {
        mutable score = 0;
        mutable triggered = 0;
        mutable quantumSensitive = 0;

        if IsStateBitSet(featureMask, 0) {
            set score += 25;
            set triggered += 1;
        }
        if IsStateBitSet(featureMask, 1) {
            set score += 20;
            set triggered += 1;
        }
        if IsStateBitSet(featureMask, 2) {
            set score += 30;
            set triggered += 1;
        }
        if IsStateBitSet(featureMask, 3) {
            set score += 12;
            set triggered += 1;
            set quantumSensitive += 1;
        }
        if IsStateBitSet(featureMask, 4) {
            set score += 25;
            set triggered += 1;
            set quantumSensitive += 1;
        }
        if IsStateBitSet(featureMask, 5) {
            set score += 12;
            set triggered += 1;
            set quantumSensitive += 1;
        }
        if IsStateBitSet(featureMask, 6) {
            set score += 15;
            set triggered += 1;
        }
        if IsStateBitSet(featureMask, 7) {
            set score += 15;
            set triggered += 1;
            set quantumSensitive += 1;
        }

        if score > 100 {
            set score = 100;
        }

        // 0 = classical allowed, 1 = hybrid required, 2 = block/reject.
        mutable requiredAuthMode = 0;
        if quantumSensitive > 0 or score >= 20 {
            set requiredAuthMode = 1;
        }
        if score >= 70 or IsStateBitSet(featureMask, 2) {
            set requiredAuthMode = 2;
        }
        return (score, quantumSensitive, requiredAuthMode, triggered);
    }
}

namespace AntiQSignature {
    /// Exhaustively explores all 4^3 action sequences.
    /// Actions: 0 use leaf0, 1 replay leaf0, 2 freeze, 3 use leaf1.
    operation RunTransactionSequenceHarness() : (Int, Int, Int) {
        mutable hardenedViolations = 0;
        mutable mutantViolations = 0;

        for encodedSequence in 0..63 {
            mutable remaining = encodedSequence;
            mutable hardenedFrozen = false;
            mutable hardenedLeaf0 = false;
            mutable hardenedLeaf1 = false;
            mutable hardenedAcceptedAfterFreeze = false;

            mutable mutantFrozen = false;
            mutable mutantLeaf0Uses = 0;
            mutable mutantLeaf1Uses = 0;
            mutable mutantAcceptedAfterFreeze = false;

            for _ in 0..2 {
                let action = remaining % 4;
                set remaining /= 4;

                if action == 2 {
                    set hardenedFrozen = true;
                    set mutantFrozen = true;
                } else {
                    let usesLeaf0 = action == 0 or action == 1;

                    if not hardenedFrozen {
                        if usesLeaf0 {
                            if not hardenedLeaf0 {
                                set hardenedLeaf0 = true;
                            }
                        } else {
                            if not hardenedLeaf1 {
                                set hardenedLeaf1 = true;
                            }
                        }
                    } else {
                        set hardenedAcceptedAfterFreeze = false;
                    }

                    // Mutant accepts after freeze and does not consume one-time leaves.
                    if mutantFrozen {
                        set mutantAcceptedAfterFreeze = true;
                    }
                    if usesLeaf0 {
                        set mutantLeaf0Uses += 1;
                    } else {
                        set mutantLeaf1Uses += 1;
                    }
                }
            }

            if hardenedAcceptedAfterFreeze {
                set hardenedViolations += 1;
            }
            if mutantAcceptedAfterFreeze or mutantLeaf0Uses > 1 or mutantLeaf1Uses > 1 {
                set mutantViolations += 1;
            }
        }
        return (64, hardenedViolations, mutantViolations);
    }
}

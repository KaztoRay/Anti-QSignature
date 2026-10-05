namespace AntiQSignature {
    import Std.Arrays.*;
    import Std.Canon.*;
    import Std.Measurement.*;
    import Std.Intrinsic.*;

    operation MarkTargetState(register : Qubit[], zeroBitIndexes : Int[]) : Unit is Adj {
        for index in zeroBitIndexes {
            X(register[index]);
        }
        Controlled Z(Most(register), Tail(register));
        for index in zeroBitIndexes {
            X(register[index]);
        }
    }

    operation ReflectAttackState(register : Qubit[]) : Unit is Adj {
        ApplyToEachA(H, register);
        ApplyToEachA(X, register);
        Controlled Z(Most(register), Tail(register));
        ApplyToEachA(X, register);
        ApplyToEachA(H, register);
    }

    /// Searches for the known mutant counterexample 0b0100001:
    /// owner=true, pq=false, guardian=false, frozen=false,
    /// approvedCode=false, correctNonce=true, highValue=false.
    operation RunWalletAttackHarness(iterations : Int) : Result[] {
        use register = Qubit[7];
        ApplyToEach(H, register);
        for _ in 1..iterations {
            MarkTargetState(register, [1, 2, 3, 4, 6]);
            ReflectAttackState(register);
        }
        let result = MeasureEachZ(register);
        ResetAll(register);
        return result;
    }

    /// One Grover oracle plus diffusion step, used for scalable QRE comparisons.
    operation EstimateAttackRound(registerSize : Int) : Unit {
        use register = Qubit[registerSize];
        ApplyToEach(H, register);
        Controlled Z(Most(register), Tail(register));
        ReflectAttackState(register);
        ResetAll(register);
    }
}

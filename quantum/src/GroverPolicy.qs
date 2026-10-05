namespace AntiQSignature {
    import Std.Arrays.*;
    import Std.Canon.*;
    import Std.Measurement.*;
    import Std.Intrinsic.*;

    /// The seven qubits model attacker-controlled wallet conditions. The all-one
    /// state is the bounded counterexample: compromised owner, missing PQ proof,
    /// missing guardian, changed code, replayed nonce, frozen bypass, high value.
    operation MarkAllOnes(register : Qubit[]) : Unit is Adj + Ctl {
        Controlled Z(Most(register), Tail(register));
    }

    operation ReflectAboutUniform(register : Qubit[]) : Unit is Adj {
        ApplyToEachA(H, register);
        ApplyToEachA(X, register);
        MarkAllOnes(register);
        ApplyToEachA(X, register);
        ApplyToEachA(H, register);
    }

    operation RunGroverProbe(qubitCount : Int, maxIterations : Int) : Result[] {
        use register = Qubit[qubitCount];
        ApplyToEach(H, register);
        for _ in 1..maxIterations {
            MarkAllOnes(register);
            ReflectAboutUniform(register);
        }
        let results = MeasureEachZ(register);
        ResetAll(register);
        return results;
    }
}

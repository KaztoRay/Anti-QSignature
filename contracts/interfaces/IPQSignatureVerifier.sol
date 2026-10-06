// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPQSignatureVerifier {
    function verify(bytes32 digest, bytes calldata signature, bytes32 keyCommitment)
        external
        view
        returns (bool);
}


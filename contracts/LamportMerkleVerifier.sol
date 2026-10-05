// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Research verifier for Merkle-committed Lamport one-time signatures.
/// @dev Hash-based and quantum-resistant under the security assumptions of keccak256.
///      The calldata and gas costs are intentionally explicit; production chains
///      should use a standardized PQ precompile when one is available.
library LamportMerkleVerifier {
    bytes32 internal constant DOMAIN = keccak256("ANTI_Q_LAMPORT_V1");

    struct Proof {
        uint256 leafIndex;
        bytes32[256] revealedSecrets;
        bytes32[512] publicKey;
        bytes32[] merkleProof;
    }

    function publicKeyLeaf(bytes32[512] calldata publicKey) internal pure returns (bytes32) {
        bytes32 accumulator = DOMAIN;
        for (uint256 i; i < 256; ++i) {
            accumulator = keccak256(
                abi.encodePacked(accumulator, publicKey[i * 2], publicKey[i * 2 + 1])
            );
        }
        return accumulator;
    }

    function verify(bytes32 digest, Proof calldata proof, bytes32 merkleRoot)
        internal
        pure
        returns (bool)
    {
        uint256 digestValue = uint256(digest);
        for (uint256 i; i < 256; ++i) {
            uint256 bit = (digestValue >> (255 - i)) & 1;
            bytes32 expectedCommitment = proof.publicKey[i * 2 + bit];
            if (keccak256(abi.encodePacked(proof.revealedSecrets[i])) != expectedCommitment) {
                return false;
            }
        }

        bytes32 node = publicKeyLeaf(proof.publicKey);
        uint256 index = proof.leafIndex;
        for (uint256 i; i < proof.merkleProof.length; ++i) {
            bytes32 sibling = proof.merkleProof[i];
            node = index & 1 == 0
                ? keccak256(abi.encodePacked(node, sibling))
                : keccak256(abi.encodePacked(sibling, node));
            index >>= 1;
        }
        return node == merkleRoot;
    }
}


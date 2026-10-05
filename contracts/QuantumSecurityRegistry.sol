// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Append-only linkage between deployed code and an off-chain Q# analysis manifest.
contract QuantumSecurityRegistry {
    struct Attestation {
        bytes32 runtimeCodeHash;
        bytes32 sourceManifestHash;
        bytes32 quantumReportHash;
        uint64 registeredAt;
        uint32 codeEpoch;
    }

    address public immutable administrator;
    mapping(address target => Attestation) public attestations;

    event Attested(
        address indexed target,
        bytes32 indexed runtimeCodeHash,
        bytes32 sourceManifestHash,
        bytes32 quantumReportHash,
        uint32 codeEpoch
    );

    error Unauthorized();
    error EmptyCode();
    error EpochDidNotIncrease();

    constructor(address initialAdministrator) {
        require(initialAdministrator != address(0), "administrator is zero");
        administrator = initialAdministrator;
    }

    function attest(
        address target,
        bytes32 sourceManifestHash,
        bytes32 quantumReportHash,
        uint32 codeEpoch
    ) external {
        if (msg.sender != administrator) revert Unauthorized();
        bytes32 runtimeCodeHash = target.codehash;
        if (runtimeCodeHash == bytes32(0)) revert EmptyCode();
        if (codeEpoch <= attestations[target].codeEpoch) revert EpochDidNotIncrease();
        attestations[target] = Attestation({
            runtimeCodeHash: runtimeCodeHash,
            sourceManifestHash: sourceManifestHash,
            quantumReportHash: quantumReportHash,
            registeredAt: uint64(block.timestamp),
            codeEpoch: codeEpoch
        });
        emit Attested(target, runtimeCodeHash, sourceManifestHash, quantumReportHash, codeEpoch);
    }

    function codeIsIntact(address target) external view returns (bool) {
        Attestation memory item = attestations[target];
        return item.codeEpoch != 0 && item.runtimeCodeHash == target.codehash;
    }
}


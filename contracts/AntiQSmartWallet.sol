// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LamportMerkleVerifier} from "./LamportMerkleVerifier.sol";

/// @notice Hybrid ECDSA + hash-based one-time-signature research wallet.
contract AntiQSmartWallet {
    using LamportMerkleVerifier for bytes32;

    bytes32 internal constant EXECUTE_TYPEHASH = keccak256(
        "AntiQExecute(uint256 chainId,address wallet,uint256 nonce,address target,uint256 value,bytes32 dataHash,uint32 codeEpoch,uint32 policyEpoch)"
    );
    uint256 internal constant SECP256K1N_DIV_2 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable owner;
    bytes32 public immutable pqRoot;
    uint32 public immutable codeEpoch;
    uint32 public immutable policyEpoch;
    uint256 public nonce;
    bool public frozen;
    mapping(uint256 leafIndex => bool) public usedLeaf;

    error Unauthorized();
    error InvalidClassicalSignature();
    error InvalidPostQuantumSignature();
    error LamportLeafAlreadyUsed();
    error WalletFrozen();
    error ZeroTarget();
    error CallFailed(bytes reason);

    event Executed(uint256 indexed nonce, uint256 indexed leafIndex, address indexed target, uint256 value);
    event Frozen(address indexed actor);

    constructor(address initialOwner, bytes32 initialPqRoot, uint32 initialCodeEpoch, uint32 initialPolicyEpoch) {
        require(initialOwner != address(0), "owner is zero");
        require(initialPqRoot != bytes32(0), "PQ root is zero");
        owner = initialOwner;
        pqRoot = initialPqRoot;
        codeEpoch = initialCodeEpoch;
        policyEpoch = initialPolicyEpoch;
    }

    receive() external payable {}

    function operationDigest(address target, uint256 value, bytes calldata data)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                block.chainid,
                address(this),
                nonce,
                target,
                value,
                keccak256(data),
                codeEpoch,
                policyEpoch
            )
        );
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata classicalSignature,
        LamportMerkleVerifier.Proof calldata quantumProof
    ) external returns (bytes memory result) {
        if (frozen) revert WalletFrozen();
        if (target == address(0)) revert ZeroTarget();
        if (usedLeaf[quantumProof.leafIndex]) revert LamportLeafAlreadyUsed();

        bytes32 digest = operationDigest(target, value, data);
        if (_recover(digest, classicalSignature) != owner) revert InvalidClassicalSignature();
        if (!digest.verify(quantumProof, pqRoot)) revert InvalidPostQuantumSignature();

        uint256 consumedNonce = nonce;
        usedLeaf[quantumProof.leafIndex] = true;
        unchecked {
            nonce = consumedNonce + 1;
        }

        (bool success, bytes memory returned) = target.call{value: value}(data);
        if (!success) revert CallFailed(returned);
        emit Executed(consumedNonce, quantumProof.leafIndex, target, value);
        return returned;
    }

    /// @notice Classical owner may only reduce risk by freezing; it cannot move funds.
    function emergencyFreeze() external {
        if (msg.sender != owner) revert Unauthorized();
        frozen = true;
        emit Frozen(msg.sender);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1N_DIV_2 || (v != 27 && v != 28)) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}

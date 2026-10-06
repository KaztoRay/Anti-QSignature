// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount, PackedUserOperation} from "./interfaces/IAccount.sol";
import {IPQSignatureVerifier} from "./interfaces/IPQSignatureVerifier.sol";

/// @notice ERC-4337 account with hybrid classical and post-quantum authorization.
/// @dev The PQ algorithm is crypto-agile through IPQSignatureVerifier. Deployments
///      should pin a reviewed verifier or a chain-native PQ precompile adapter.
contract AntiQ4337Account is IAccount {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant SECP256K1N_DIV_2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable entryPoint;
    address public immutable owner;
    IPQSignatureVerifier public immutable pqVerifier;
    bytes32 public pqKeyCommitment;
    uint32 public keyEpoch;
    uint32 public immutable codeEpoch;
    uint32 public immutable policyEpoch;

    error OnlyEntryPoint();
    error OnlySelf();
    error ZeroAddress();
    error InvalidKeyCommitment();
    error ExecutionFailed(bytes reason);

    event AccountCall(address indexed target, uint256 value, bytes4 selector);
    event PQKeyRotated(bytes32 indexed previousCommitment, bytes32 indexed newCommitment, uint32 keyEpoch);

    constructor(
        address initialEntryPoint,
        address initialOwner,
        IPQSignatureVerifier initialPqVerifier,
        bytes32 initialPqKeyCommitment,
        uint32 initialCodeEpoch,
        uint32 initialPolicyEpoch
    ) {
        if (initialEntryPoint == address(0) || initialOwner == address(0) || address(initialPqVerifier) == address(0)) revert ZeroAddress();
        if (initialPqKeyCommitment == bytes32(0)) revert InvalidKeyCommitment();
        entryPoint = initialEntryPoint;
        owner = initialOwner;
        pqVerifier = initialPqVerifier;
        pqKeyCommitment = initialPqKeyCommitment;
        keyEpoch = 1;
        codeEpoch = initialCodeEpoch;
        policyEpoch = initialPolicyEpoch;
    }

    receive() external payable {}

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert OnlyEntryPoint();
        _;
    }

    function validationDigest(bytes32 userOpHash) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(userOpHash, block.chainid, address(this), entryPoint, codeEpoch, policyEpoch, keyEpoch)
            );
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        (bytes memory classicalSignature, bytes memory quantumSignature) = abi.decode(userOp.signature, (bytes, bytes));
        bytes32 digest = validationDigest(userOpHash);

        bool classicalValid = _recover(digest, classicalSignature) == owner;
        bool quantumValid = pqVerifier.verify(digest, quantumSignature, pqKeyCommitment);
        bool senderValid = userOp.sender == address(this);

        if (missingAccountFunds != 0) {
            (bool funded,) = payable(msg.sender).call{value: missingAccountFunds}("");
            funded;
        }
        return classicalValid && quantumValid && senderValid ? 0 : SIG_VALIDATION_FAILED;
    }

    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyEntryPoint
        returns (bytes memory result)
    {
        if (target == address(0)) revert ZeroAddress();
        (bool success, bytes memory returned) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed(returned);
        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        emit AccountCall(target, value, selector);
        return returned;
    }

    /// @notice Rotates the PQ public-key commitment through an authorized
    ///         EntryPoint operation that calls this account itself.
    /// @dev Including keyEpoch in validationDigest invalidates signatures made
    ///      for every previous key generation, even if a verifier is reused.
    function rotatePQKey(bytes32 newCommitment) external {
        if (msg.sender != address(this)) revert OnlySelf();
        if (newCommitment == bytes32(0) || newCommitment == pqKeyCommitment) {
            revert InvalidKeyCommitment();
        }
        bytes32 previousCommitment = pqKeyCommitment;
        pqKeyCommitment = newCommitment;
        keyEpoch += 1;
        emit PQKeyRotated(previousCommitment, newCommitment, keyEpoch);
    }

    function _recover(bytes32 digest, bytes memory signature) private pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (uint256(s) > SECP256K1N_DIV_2 || (v != 27 && v != 28)) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}

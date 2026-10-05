// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A small, auditable policy kernel used by the scanner and Foundry fuzz tests.
contract AntiQPolicy {
    address public immutable owner;
    uint256 public immutable dailyLimit;
    uint256 public nonce;
    uint256 public spentToday;
    bool public frozen;
    bytes32 public immutable approvedCodeHash;

    error Unauthorized();

    constructor(address initialOwner, uint256 initialDailyLimit, bytes32 initialCodeHash) {
        require(initialOwner != address(0), "owner is zero");
        require(initialDailyLimit != 0, "limit is zero");
        owner = initialOwner;
        dailyLimit = initialDailyLimit;
        approvedCodeHash = initialCodeHash;
    }

    function authorize(
        address caller,
        uint256 suppliedNonce,
        uint256 amount,
        bool pqSignatureValid,
        bool guardianApproved,
        bool codeHashApproved
    ) public view returns (bool) {
        if (frozen || !codeHashApproved || approvedCodeHash == bytes32(0)) return false;
        if (caller != owner || suppliedNonce != nonce || !pqSignatureValid) return false;
        if (spentToday + amount > dailyLimit && !guardianApproved) return false;
        return true;
    }

    function consume(
        uint256 suppliedNonce,
        uint256 amount,
        bool pqSignatureValid,
        bool guardianApproved,
        bool codeHashApproved
    ) external {
        if (!authorize(msg.sender, suppliedNonce, amount, pqSignatureValid, guardianApproved, codeHashApproved)) {
            revert Unauthorized();
        }
        unchecked {
            nonce += 1;
        }
        spentToday += amount;
    }

    function emergencyFreeze() external {
        if (msg.sender != owner) revert Unauthorized();
        frozen = true;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AntiQPolicy} from "../contracts/AntiQPolicy.sol";

contract AntiQPolicyFuzzTest {
    AntiQPolicy internal policy;
    address internal constant OWNER = address(0xA11CE);

    function setUp() public {
        policy = new AntiQPolicy(OWNER, 100 ether, keccak256("approved-runtime"));
    }

    function testFuzz_UnauthorizedCallerNeverAccepted(
        address caller,
        uint256 nonce,
        uint256 amount,
        bool pq,
        bool guardian,
        bool codeOk
    ) public view {
        if (caller == OWNER) return;
        require(!policy.authorize(caller, nonce, amount, pq, guardian, codeOk));
    }

    function testFuzz_InvalidPQSignatureNeverAccepted(uint256 amount, bool guardian) public view {
        require(!policy.authorize(OWNER, policy.nonce(), amount, false, guardian, true));
    }

    function testFuzz_ReplayedOrFutureNonceNeverAccepted(uint256 suppliedNonce, uint256 amount) public view {
        if (suppliedNonce == policy.nonce()) return;
        require(!policy.authorize(OWNER, suppliedNonce, amount, true, true, true));
    }

    function testFuzz_UnapprovedCodeNeverAccepted(uint256 amount) public view {
        require(!policy.authorize(OWNER, policy.nonce(), amount, true, true, false));
    }

    function testFuzz_HighValueNeedsGuardian(uint256 amount) public view {
        amount = 100 ether + (amount % 1000 ether) + 1;
        require(!policy.authorize(OWNER, policy.nonce(), amount, true, false, true));
    }
}


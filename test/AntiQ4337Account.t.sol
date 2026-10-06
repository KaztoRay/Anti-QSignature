// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AntiQ4337Account} from "../contracts/AntiQ4337Account.sol";
import {IAccount, PackedUserOperation} from "../contracts/interfaces/IAccount.sol";
import {IPQSignatureVerifier} from "../contracts/interfaces/IPQSignatureVerifier.sol";

interface Vm4337 {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert(bytes4 selector) external;
}

contract MockPQVerifier is IPQSignatureVerifier {
    function verify(bytes32 digest, bytes calldata signature, bytes32 keyCommitment)
        external
        pure
        returns (bool)
    {
        return keccak256(signature) == keccak256(abi.encode(digest, keyCommitment));
    }
}

contract MockEntryPoint {
    function validate(IAccount account, PackedUserOperation calldata op, bytes32 userOpHash)
        external
        returns (uint256)
    {
        return account.validateUserOp(op, userOpHash, 0);
    }

    function execute(AntiQ4337Account account, address target, bytes calldata data) external {
        account.execute(target, 0, data);
    }

    receive() external payable {}
}

contract AccountReceiver {
    uint256 public number;

    function setNumber(uint256 newNumber) external {
        number = newNumber;
    }
}

contract AntiQ4337AccountTest {
    Vm4337 internal constant vm = Vm4337(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant OWNER_KEY = 0xB0B;
    bytes32 internal constant PQ_COMMITMENT = keccak256("pq-key-v1");

    MockEntryPoint internal entryPoint;
    MockPQVerifier internal verifier;
    AntiQ4337Account internal account;
    AccountReceiver internal receiver;

    function setUp() public {
        entryPoint = new MockEntryPoint();
        verifier = new MockPQVerifier();
        account = new AntiQ4337Account(
            address(entryPoint), vm.addr(OWNER_KEY), verifier, PQ_COMMITMENT, 1, 1
        );
        receiver = new AccountReceiver();
    }

    function test_ValidHybridUserOperationAndEntryPointExecution() public {
        bytes32 userOpHash = keccak256("user-operation");
        PackedUserOperation memory op = _operation(userOpHash, true);
        require(entryPoint.validate(account, op, userOpHash) == 0, "hybrid validation failed");

        bytes memory callData = abi.encodeCall(AccountReceiver.setNumber, (77));
        entryPoint.execute(account, address(receiver), callData);
        require(receiver.number() == 77, "EntryPoint execution failed");
    }

    function test_InvalidPQSignatureReturnsValidationFailure() public {
        bytes32 userOpHash = keccak256("invalid-pq-operation");
        PackedUserOperation memory op = _operation(userOpHash, false);
        require(entryPoint.validate(account, op, userOpHash) == 1, "invalid PQ signature accepted");
    }

    function test_DirectValidationOutsideEntryPointReverts() public {
        bytes32 userOpHash = keccak256("direct-operation");
        PackedUserOperation memory op = _operation(userOpHash, true);
        vm.expectRevert(AntiQ4337Account.OnlyEntryPoint.selector);
        account.validateUserOp(op, userOpHash, 0);
    }

    function _operation(bytes32 userOpHash, bool validPQ)
        internal
        returns (PackedUserOperation memory op)
    {
        bytes32 digest = account.validationDigest(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, digest);
        bytes memory classicalSignature = abi.encodePacked(r, s, v);
        bytes memory quantumSignature = validPQ
            ? abi.encode(digest, PQ_COMMITMENT)
            : abi.encode(bytes32(uint256(digest) ^ 1), PQ_COMMITMENT);
        op.sender = address(account);
        op.nonce = 0;
        op.signature = abi.encode(classicalSignature, quantumSignature);
    }
}

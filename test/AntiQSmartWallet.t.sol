// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AntiQSmartWallet} from "../contracts/AntiQSmartWallet.sol";
import {LamportMerkleVerifier} from "../contracts/LamportMerkleVerifier.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert(bytes4 selector) external;
}

contract CallReceiver {
    uint256 public number;

    function setNumber(uint256 newNumber) external {
        number = newNumber;
    }
}

contract AntiQSmartWalletTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant OWNER_KEY = 0xA11CE;
    bytes32 internal constant DOMAIN = keccak256("ANTI_Q_LAMPORT_V1");

    AntiQSmartWallet internal wallet;
    CallReceiver internal receiver;

    function setUp() public {
        bytes32[512] memory publicKey = _publicKey();
        wallet = new AntiQSmartWallet(vm.addr(OWNER_KEY), _leaf(publicKey), 1, 1);
        receiver = new CallReceiver();
    }

    function test_HybridExecutionConsumesNonceAndLamportLeaf() public {
        bytes memory data = abi.encodeCall(CallReceiver.setNumber, (42));
        bytes32 digest = wallet.operationDigest(address(receiver), 0, data);
        LamportMerkleVerifier.Proof memory proof = _proof(digest);
        bytes memory classicalSignature = _sign(digest);

        wallet.execute(address(receiver), 0, data, classicalSignature, proof);

        require(receiver.number() == 42, "call not executed");
        require(wallet.nonce() == 1, "nonce not consumed");
        require(wallet.usedLeaf(0), "Lamport leaf not consumed");

        vm.expectRevert(AntiQSmartWallet.LamportLeafAlreadyUsed.selector);
        wallet.execute(address(receiver), 0, data, classicalSignature, proof);
    }

    function test_InvalidLamportSecretIsRejected() public {
        bytes memory data = abi.encodeCall(CallReceiver.setNumber, (7));
        bytes32 digest = wallet.operationDigest(address(receiver), 0, data);
        LamportMerkleVerifier.Proof memory proof = _proof(digest);
        proof.revealedSecrets[0] = bytes32(uint256(proof.revealedSecrets[0]) ^ 1);

        vm.expectRevert(AntiQSmartWallet.InvalidPostQuantumSignature.selector);
        wallet.execute(address(receiver), 0, data, _sign(digest), proof);
    }

    function _publicKey() internal pure returns (bytes32[512] memory result) {
        for (uint256 i; i < 256; ++i) {
            result[i * 2] = keccak256(abi.encodePacked(_secret(i, 0)));
            result[i * 2 + 1] = keccak256(abi.encodePacked(_secret(i, 1)));
        }
    }

    function _proof(bytes32 digest) internal pure returns (LamportMerkleVerifier.Proof memory proof) {
        proof.leafIndex = 0;
        proof.publicKey = _publicKey();
        proof.merkleProof = new bytes32[](0);
        uint256 digestValue = uint256(digest);
        for (uint256 i; i < 256; ++i) {
            uint256 bit = (digestValue >> (255 - i)) & 1;
            proof.revealedSecrets[i] = _secret(i, bit);
        }
    }

    function _leaf(bytes32[512] memory publicKey) internal pure returns (bytes32 accumulator) {
        accumulator = DOMAIN;
        for (uint256 i; i < 256; ++i) {
            accumulator = keccak256(
                abi.encodePacked(accumulator, publicKey[i * 2], publicKey[i * 2 + 1])
            );
        }
    }

    function _secret(uint256 index, uint256 branch) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("antiq-test-secret", index, branch));
    }

    function _sign(bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }
}

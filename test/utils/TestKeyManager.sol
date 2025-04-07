// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {KeyType, Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {Utils, WebAuthnInfo} from "webauthn-sol/test/Utils.sol";
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

struct TestKey {
    KeyType keyType;
    bytes publicKey;
    // saved to sign messages
    uint256 privateKey;
}

library TestKeyManager {
    using KeyLib for Key;

    error KeyNotSupported();

    // vm.addr(0xa11ce)
    address constant signerTestKeyAddress = 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7;

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // 0 = never expires
    uint40 internal constant DEFAULT_KEY_EXPIRY = 0;
    uint256 internal constant DEFAULT_SECP256R1_PK = uint256(keccak256("DEFAULT_SECP256R1_PK"));
    uint256 internal constant DEFAULT_SECP256K1_PK = uint256(keccak256("DEFAULT_SECP256K1_PK"));

    // Example webauthn key from Coinbase Smart Wallet
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PK =
        uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PUBLIC_X =
        12_673_873_082_346_130_924_691_454_452_779_514_193_164_883_897_088_292_420_374_917_853_190_248_779_330;
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PUBLIC_Y =
        18_542_991_761_951_108_740_563_055_453_066_386_026_290_576_689_311_603_472_268_584_080_832_751_656_013;

    // Return a Key initialized from the default constants based on the key type.
    function initDefault(KeyType keyType) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(DEFAULT_SECP256R1_PK);
            return TestKey({keyType: keyType, publicKey: abi.encode(x, y), privateKey: DEFAULT_SECP256R1_PK});
        } else if (keyType == KeyType.Secp256k1) {
            address defaultAddress = vm.addr(DEFAULT_SECP256K1_PK);
            return TestKey({keyType: keyType, publicKey: abi.encode(defaultAddress), privateKey: DEFAULT_SECP256K1_PK});
        } else if (keyType == KeyType.WebAuthnP256) {
            return TestKey({
                keyType: keyType,
                publicKey: abi.encode(DEFAULT_WEBAUTHN_P256_PUBLIC_X, DEFAULT_WEBAUTHN_P256_PUBLIC_Y),
                privateKey: DEFAULT_WEBAUTHN_P256_PK
            });
        } else {
            revert KeyNotSupported();
        }
    }

    // Create a public key derived from a seed.
    /// @dev This does not support WebAuthnP256 keys.
    function withSeed(KeyType keyType, uint256 seed) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(seed);
            return TestKey({keyType: keyType, publicKey: abi.encode(x, y), privateKey: seed});
        } else if (keyType == KeyType.Secp256k1) {
            address addr = vm.addr(seed);
            return TestKey({keyType: keyType, publicKey: abi.encode(addr), privateKey: seed});
        } else {
            revert KeyNotSupported();
        }
    }

    function sign(TestKey memory key, bytes32 hash) internal pure returns (bytes memory) {
        if (key.keyType == KeyType.P256) {
            (bytes32 r, bytes32 s) = vm.signP256(key.privateKey, hash);
            return abi.encodePacked(r, s);
        } else if (key.keyType == KeyType.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key.privateKey, hash);
            return abi.encodePacked(r, s, v);
        } else if (key.keyType == KeyType.WebAuthnP256) {
            WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(hash);
            (bytes32 r, bytes32 s) = vm.signP256(key.privateKey, webAuthn.messageHash);
            return abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: uint256(r),
                    s: uint256(s)
                })
            );
        } else {
            revert KeyNotSupported();
        }
    }

    function toKey(TestKey memory key) internal pure returns (Key memory) {
        return Key({keyType: key.keyType, publicKey: key.publicKey});
    }

    function toKeyHash(TestKey memory key) internal pure returns (bytes32) {
        return toKey(key).hash();
    }
}

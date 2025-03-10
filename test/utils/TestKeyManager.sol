// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {KeyType, Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

struct TestKey {
    uint40 expiry;
    KeyType keyType;
    bool isSuperAdmin;
    bytes publicKey;
    // saved to sign messages
    uint256 privateKey;
}

library TestKeyManager {
    using KeyLib for Key;

    error KeyNotSupported();

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // 0 = never expires
    uint40 internal constant DEFAULT_KEY_EXPIRY = 0;
    uint256 internal constant DEFAULT_SECP256R1_PK = 0xff;
    uint256 internal constant DEFAULT_SECP256K1_PK = 0xb0b;

    // Return a Key initialized from the default constants based on the key type.
    function initDefault(KeyType keyType) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(DEFAULT_SECP256R1_PK);
            return TestKey({
                expiry: DEFAULT_KEY_EXPIRY,
                keyType: keyType,
                isSuperAdmin: false,
                publicKey: abi.encodePacked(x, y),
                privateKey: DEFAULT_SECP256R1_PK
            });
        } else if (keyType == KeyType.Secp256k1) {
            address defaultAddress = vm.addr(DEFAULT_SECP256K1_PK);
            return TestKey({
                expiry: DEFAULT_KEY_EXPIRY,
                keyType: keyType,
                isSuperAdmin: false,
                publicKey: abi.encodePacked(defaultAddress),
                privateKey: DEFAULT_SECP256K1_PK
            });
        } else {
            revert KeyNotSupported();
        }
    }

    // Create a public key derived from a seed.
    function withSeed(KeyType keyType, uint256 seed) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(seed);
            return TestKey({
                expiry: DEFAULT_KEY_EXPIRY,
                keyType: keyType,
                isSuperAdmin: false,
                publicKey: abi.encodePacked(x, y),
                privateKey: seed
            });
        } else if (keyType == KeyType.Secp256k1) {
            address addr = vm.addr(seed);
            return TestKey({
                expiry: DEFAULT_KEY_EXPIRY,
                keyType: keyType,
                isSuperAdmin: false,
                publicKey: abi.encodePacked(addr),
                privateKey: seed
            });
        } else {
            revert KeyNotSupported();
        }
    }

    // Update a Key with a new expiry.
    function withExpiry(TestKey memory key, uint40 expiry) internal pure returns (TestKey memory) {
        return TestKey({
            expiry: expiry,
            keyType: key.keyType,
            isSuperAdmin: key.isSuperAdmin,
            publicKey: key.publicKey,
            privateKey: key.privateKey
        });
    }

    // Update a Key with a new super admin status.
    function withSuperAdmin(TestKey memory key, bool isSuperAdmin) internal pure returns (TestKey memory) {
        return TestKey({
            expiry: key.expiry,
            keyType: key.keyType,
            isSuperAdmin: isSuperAdmin,
            publicKey: key.publicKey,
            privateKey: key.privateKey
        });
    }

    function sign(TestKey memory key, bytes32 hash) internal pure returns (bytes memory) {
        if (key.keyType == KeyType.P256) {
            (bytes32 r, bytes32 s) = vm.signP256(key.privateKey, hash);
            return abi.encodePacked(r, s);
        } else if (key.keyType == KeyType.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key.privateKey, hash);
            return abi.encodePacked(v, r, s);
        } else {
            revert KeyNotSupported();
        }
    }

    function toKey(TestKey memory key) internal pure returns (Key memory) {
        return Key({expiry: key.expiry, keyType: key.keyType, isSuperAdmin: key.isSuperAdmin, publicKey: key.publicKey});
    }

    function toKeyHash(TestKey memory key) internal pure returns (bytes32) {
        return toKey(key).hash();
    }
}

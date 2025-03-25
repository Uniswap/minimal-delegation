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
    uint256 internal constant DEFAULT_SECP256R1_PK = uint256(keccak256("DEFAULT_SECP256R1_PK"));
    uint256 internal constant DEFAULT_SECP256K1_PK = uint256(keccak256("DEFAULT_SECP256K1_PK"));

    // N (order of G) from P256 curve
    uint256 constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    // N/2 for excluding higher order `s` values
    uint256 constant HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

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
            s = toNonMalleable(s);
            return abi.encodePacked(r, s);
        } else if (key.keyType == KeyType.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key.privateKey, hash);
            return abi.encodePacked(r, s, v);
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

    /// @dev This is unaudited and may not be secure.
    function toNonMalleable(bytes32 s) internal pure returns (bytes32) {
        // If s > N/2, transform it to the lower value
        if (uint256(s) > HALF_N) {
            s = bytes32(N - uint256(s));
        }
        return s;
    }
}

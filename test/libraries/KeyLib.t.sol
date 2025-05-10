// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {KeyType, Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {MockKeyLib} from "../utils/MockKeyLib.sol";
import {TestKey, TestKeyManager} from "../utils/TestKeyManager.sol";

contract KeyLibTest is Test {
    using KeyLib for Key;
    using TestKeyManager for TestKey;

    MockKeyLib mockKeyLib;

    Key mockRootKey;

    function setUp() public {
        mockKeyLib = new MockKeyLib();
        mockRootKey = Key({keyType: KeyType.Secp256k1, publicKey: abi.encode(address(mockKeyLib))});
    }

    function test_isRootKey_keyHash_fuzz(bytes32 keyHash) public view {
        assertEq(mockKeyLib.isRootKey(keyHash), keyHash == KeyLib.ROOT_KEY_HASH);
    }

    function test_isRootKey_keyTypeAndAddressThis() public view {
        assertEq(mockKeyLib.isRootKey(mockRootKey), true);
    }

    function test_toRootKey_isRootKey() public view {
        assertEq(mockKeyLib.toRootKey().hash(), mockRootKey.hash());
    }

    function test_toKeyHash_addressThis_returns_RootKeyHash() public view {
        assertEq(mockKeyLib.toKeyHash(address(mockKeyLib)), KeyLib.ROOT_KEY_HASH);
    }

    function test_toKeyHash_caller_returns_correctKeyHash_fuzz(address caller) public view {
        if (caller == address(mockKeyLib)) {
            assertEq(mockKeyLib.toKeyHash(caller), KeyLib.ROOT_KEY_HASH);
        } else {
            assertEq(
                mockKeyLib.toKeyHash(caller),
                KeyLib.hash(Key({keyType: KeyType.Secp256k1, publicKey: abi.encode(caller)}))
            );
        }
    }

    function test_verify_secp256k1_compactSignature_valid_fuzz(bytes32 digest) public view {
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        (bytes32 r, bytes32 vs) = vm.signCompact(testKey.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, vs);
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), true);
    }

    function test_verify_secp256k1_compactSignature_invalid_fuzz(bytes32 digest) public view {
        bytes32 invalidDigest = keccak256(abi.encode(digest));
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        // Sign the invalid digest
        (bytes32 r, bytes32 vs) = vm.signCompact(testKey.privateKey, invalidDigest);
        bytes memory signature = abi.encodePacked(r, vs);
        // Try to verify against the original digest
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), false);
    }

    function test_verify_secp256k1_signature_valid_fuzz(bytes32 digest) public view {
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testKey.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), true);
    }

    function test_verify_secp256k1_signature_invalid_fuzz(bytes32 digest) public view {
        bytes32 invalidDigest = keccak256(abi.encode(digest));
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        // Sign the invalid digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testKey.privateKey, invalidDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        // Try to verify against the original digest
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), false);
    }

    function test_verify_p256_signature_valid_fuzz(bytes32 digest) public view {
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.P256);
        (bytes32 r, bytes32 s) = vm.signP256(testKey.privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s);
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), true);
    }

    function test_verify_p256_signature_invalid_fuzz(bytes32 digest) public view {
        bytes32 invalidDigest = keccak256(abi.encode(digest));
        TestKey memory testKey = TestKeyManager.initDefault(KeyType.P256);
        // Sign the invalid digest
        (bytes32 r, bytes32 s) = vm.signP256(testKey.privateKey, invalidDigest);
        bytes memory signature = abi.encodePacked(r, s);
        // Try to verify against the original digest
        assertEq(KeyLib.verify(testKey.toKey(), digest, signature), false);
    }
}

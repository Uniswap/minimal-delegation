// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {Key, KeyType, KeyLib} from "../src/lib/KeyLib.sol";

contract MinimalDelegationTest is DelegationHandler {
    using KeyLib for Key;

    error KeyDoesNotExist();

    function setUp() public {
        setUpDelegation();
    }

    function test_authorize() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        minimalDelegation.authorize(mockSecp256k1Key);
        vm.snapshotGasLastCall("authorize");

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(minimalDelegation.keyCount(), 1);
    }

    function test_authorize_expiryUpdated() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        minimalDelegation.authorize(mockSecp256k1Key);

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(minimalDelegation.keyCount(), 1);

        mockSecp256k1Key =
            Key(uint40(block.timestamp + 3600), KeyType.Secp256k1, true, abi.encodePacked(mockSecp256k1PublicKey));
        keyHash = mockSecp256k1Key.hash();
        // already authorized key should be updated
        minimalDelegation.authorize(mockSecp256k1Key);

        fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        // key count should remain the same
        assertEq(minimalDelegation.keyCount(), 1);
    }

    function test_revoke() public {
        // first authorize the key
        bytes32 keyHash = minimalDelegation.authorize(mockSecp256k1Key);
        assertEq(minimalDelegation.keyCount(), 1);

        // then revoke the key
        minimalDelegation.revoke(keyHash);
        vm.snapshotGasLastCall("revoke");

        // then expect the key to not exist
        vm.expectRevert(KeyDoesNotExist.selector);
        minimalDelegation.getKey(keyHash);
        assertEq(minimalDelegation.keyCount(), 0);
    }

    function test_revoke_revertsWithKeyDoesNotExist() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.expectRevert(KeyDoesNotExist.selector);
        minimalDelegation.revoke(keyHash);
    }

    function test_keyCount() public {
        minimalDelegation.authorize(mockSecp256k1Key);
        minimalDelegation.authorize(mockSecp256k1Key2);

        assertEq(minimalDelegation.keyCount(), 2);
    }

    function test_keyAt() public {
        minimalDelegation.authorize(mockSecp256k1Key);
        minimalDelegation.authorize(mockSecp256k1Key2);

        // 2 keys authorized
        assertEq(minimalDelegation.keyCount(), 2);

        Key memory key = minimalDelegation.keyAt(0);
        assertEq(key.expiry, 0);
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, true);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey));

        key = minimalDelegation.keyAt(1);
        assertEq(key.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, false);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey2));

        // revoke first key
        minimalDelegation.revoke(mockSecp256k1Key.hash());
        // indexes should be shifted
        vm.expectRevert();
        minimalDelegation.keyAt(1);

        key = minimalDelegation.keyAt(0);
        assertEq(key.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, false);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey2));

        // only one key should be left
        assertEq(minimalDelegation.keyCount(), 1);
    }
}

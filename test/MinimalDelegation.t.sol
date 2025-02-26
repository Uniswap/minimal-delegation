// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {Key, KeyType, KeyLib} from "../src/lib/KeyLib.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";

contract MinimalDelegationTest is DelegationHandler {
    using KeyLib for Key;

    event Authorized(bytes32 indexed keyHash, Key key);
    event Revoked(bytes32 indexed keyHash);

    function setUp() public {
        setUpDelegation();
    }

    function test_authorize() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        vm.expectEmit(true, false, false, true);
        emit Authorized(keyHash, mockSecp256k1Key);

        vm.prank(address(minimalDelegation));
        minimalDelegation.authorize(mockSecp256k1Key);
        vm.snapshotGasLastCall("authorize");

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(minimalDelegation.keyCount(), 1);
    }

    function test_authorize_revertsWithUnauthorized() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        minimalDelegation.authorize(mockSecp256k1Key);
    }

    function test_authorize_expiryUpdated() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.startPrank(address(minimalDelegation));
        minimalDelegation.authorize(mockSecp256k1Key);

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(minimalDelegation.keyCount(), 1);

        mockSecp256k1Key.expiry = uint40(block.timestamp + 3600);
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
        vm.startPrank(address(minimalDelegation));
        bytes32 keyHash = minimalDelegation.authorize(mockSecp256k1Key);
        assertEq(minimalDelegation.keyCount(), 1);

        vm.expectEmit(true, false, false, true);
        emit Revoked(keyHash);

        // then revoke the key
        minimalDelegation.revoke(keyHash);
        vm.snapshotGasLastCall("revoke");

        // then expect the key to not exist
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        minimalDelegation.getKey(keyHash);
        assertEq(minimalDelegation.keyCount(), 0);
    }

    function test_revoke_revertsWithUnauthorized() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.expectRevert(IERC7821.Unauthorized.selector);
        minimalDelegation.revoke(keyHash);
    }

    function test_revoke_revertsWithKeyDoesNotExist() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        vm.prank(address(minimalDelegation));
        minimalDelegation.revoke(keyHash);
    }

    function test_keyCount() public {
        vm.startPrank(address(minimalDelegation));
        minimalDelegation.authorize(mockSecp256k1Key);
        minimalDelegation.authorize(mockSecp256k1Key2);

        assertEq(minimalDelegation.keyCount(), 2);
    }

    /// forge-config: default.fuzz.runs = 100
    /// forge-config: ci.fuzz.runs = 500
    function test_fuzz_keyCount(uint8 numKeys) public {
        Key memory mockSecp256k1Key;
        string memory publicKey = "";
        address mockSecp256k1PublicKey;
        for (uint256 i = 0; i < numKeys; i++) {
            mockSecp256k1PublicKey = makeAddr(string(abi.encodePacked(publicKey, i)));
            mockSecp256k1Key = Key(0, KeyType.Secp256k1, true, abi.encodePacked(mockSecp256k1PublicKey));
            vm.prank(address(minimalDelegation));
            minimalDelegation.authorize(mockSecp256k1Key);
        }

        assertEq(minimalDelegation.keyCount(), numKeys);
    }

    function test_keyAt() public {
        vm.startPrank(address(minimalDelegation));
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

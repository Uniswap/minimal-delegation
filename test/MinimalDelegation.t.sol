// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {Key, KeyType, KeyLib} from "../src/libraries/KeyLib.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC4337Account} from "../src/ERC4337Account.sol";

contract MinimalDelegationTest is DelegationHandler {
    using KeyLib for Key;

    event Authorized(bytes32 indexed keyHash, Key key);
    event Revoked(bytes32 indexed keyHash);

    function setUp() public {
        setUpDelegation();
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_authorize_gas() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        vm.expectEmit(true, false, false, true);
        emit Authorized(keyHash, mockSecp256k1Key);

        vm.prank(address(signerAccount));
        signerAccount.authorize(mockSecp256k1Key);
        vm.snapshotGasLastCall("authorize");
    }

    function test_authorize() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        vm.expectEmit(true, false, false, true);
        emit Authorized(keyHash, mockSecp256k1Key);

        vm.prank(address(signerAccount));
        signerAccount.authorize(mockSecp256k1Key);

        Key memory fetchedKey = signerAccount.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(signerAccount.keyCount(), 1);
    }

    function test_authorize_revertsWithUnauthorized() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.authorize(mockSecp256k1Key);
    }

    function test_authorize_expiryUpdated() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.startPrank(address(signerAccount));
        signerAccount.authorize(mockSecp256k1Key);

        Key memory fetchedKey = signerAccount.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        assertEq(signerAccount.keyCount(), 1);

        mockSecp256k1Key.expiry = uint40(block.timestamp + 3600);
        // already authorized key should be updated
        signerAccount.authorize(mockSecp256k1Key);

        fetchedKey = signerAccount.getKey(keyHash);
        assertEq(fetchedKey.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
        // key count should remain the same
        assertEq(signerAccount.keyCount(), 1);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_revoke_gas() public {
        // first authorize the key
        vm.startPrank(address(signerAccount));
        bytes32 keyHash = signerAccount.authorize(mockSecp256k1Key);
        assertEq(signerAccount.keyCount(), 1);

        vm.expectEmit(true, false, false, true);
        emit Revoked(keyHash);

        // then revoke the key
        signerAccount.revoke(keyHash);
        vm.snapshotGasLastCall("revoke");
    }

    function test_revoke() public {
        // first authorize the key
        vm.startPrank(address(signerAccount));
        bytes32 keyHash = signerAccount.authorize(mockSecp256k1Key);
        assertEq(signerAccount.keyCount(), 1);

        vm.expectEmit(true, false, false, true);
        emit Revoked(keyHash);

        // then revoke the key
        signerAccount.revoke(keyHash);

        // then expect the key to not exist
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        signerAccount.getKey(keyHash);
        assertEq(signerAccount.keyCount(), 0);
    }

    function test_revoke_revertsWithUnauthorized() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.revoke(keyHash);
    }

    function test_revoke_revertsWithKeyDoesNotExist() public {
        bytes32 keyHash = mockSecp256k1Key.hash();
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        vm.prank(address(signerAccount));
        signerAccount.revoke(keyHash);
    }

    function test_keyCount() public {
        vm.startPrank(address(signerAccount));
        signerAccount.authorize(mockSecp256k1Key);
        signerAccount.authorize(mockSecp256k1Key2);

        assertEq(signerAccount.keyCount(), 2);
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
            vm.prank(address(signerAccount));
            signerAccount.authorize(mockSecp256k1Key);
        }

        assertEq(signerAccount.keyCount(), numKeys);
    }

    function test_keyAt() public {
        vm.startPrank(address(signerAccount));
        signerAccount.authorize(mockSecp256k1Key);
        signerAccount.authorize(mockSecp256k1Key2);

        // 2 keys authorized
        assertEq(signerAccount.keyCount(), 2);

        Key memory key = signerAccount.keyAt(0);
        assertEq(key.expiry, 0);
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, true);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey));

        key = signerAccount.keyAt(1);
        assertEq(key.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, false);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey2));

        // revoke first key
        signerAccount.revoke(mockSecp256k1Key.hash());
        // indexes should be shifted
        vm.expectRevert();
        signerAccount.keyAt(1);

        key = signerAccount.keyAt(0);
        assertEq(key.expiry, uint40(block.timestamp + 3600));
        assertEq(uint256(key.keyType), uint256(KeyType.Secp256k1));
        assertEq(key.isSuperAdmin, false);
        assertEq(key.publicKey, abi.encodePacked(mockSecp256k1PublicKey2));

        // only one key should be left
        assertEq(signerAccount.keyCount(), 1);
    }

    function test_updateEntryPoint_revertsWithUnauthorized() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.updateEntryPoint(address(entryPoint));
    }

    function test_validateUserOp_revertsWithNotEntryPoint() public {
        // Even with a prank, this should revert if not enabled on the account.
        vm.startPrank(address(entryPoint));
        PackedUserOperation memory userOp;
        vm.expectRevert(IERC4337Account.NotEntryPoint.selector);
        signerAccount.validateUserOp(userOp, "", 0);
    }

    function test_validateUserOp_validSignature() public {
        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
        PackedUserOperation memory userOp;
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 valid = signerAccount.validateUserOp(userOp, userOpHash, 0);
        vm.snapshotGasLastCall("validateUserOp_no_missingAccountFunds");
        assertEq(valid, 0); // 0 is valid
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_validateUserOp_validSignature_gas() public {
        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
        PackedUserOperation memory userOp;
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        signerAccount.validateUserOp(userOp, userOpHash, 0);
        vm.snapshotGasLastCall("validateUserOp_no_missingAccountFunds");
    }

    function test_validateUserOp_invalidSignature() public {
        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
        PackedUserOperation memory userOp;
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // incorrect private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1234, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 valid = signerAccount.validateUserOp(userOp, userOpHash, 0);
        assertEq(valid, 1); // 1 is invalid
    }

    function test_validateUserOp_missingAccountFunds() public {
        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
        PackedUserOperation memory userOp;
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        uint256 missingAccountFunds = 1e18;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        deal(address(signerAccount), 1e18);

        uint256 beforeDeposit = entryPoint.getDepositInfo(address(signerAccount)).deposit;

        vm.prank(address(entryPoint));
        uint256 valid = signerAccount.validateUserOp(userOp, userOpHash, missingAccountFunds);

        assertEq(valid, 0); // 0 is valid

        // account sent in 1e18 to the entry point and their deposit was updated
        assertEq(address(signerAccount).balance, 0);
        assertEq(entryPoint.getDepositInfo(address(signerAccount)).deposit, beforeDeposit + 1e18);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_validateUserOp_missingAccountFunds_gas() public {
        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
        PackedUserOperation memory userOp;
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        uint256 missingAccountFunds = 1e18;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        deal(address(signerAccount), 1e18);

        vm.prank(address(entryPoint));
        signerAccount.validateUserOp(userOp, userOpHash, missingAccountFunds);
        vm.snapshotGasLastCall("validateUserOp_missingAccountFunds");
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {Key, KeyType, KeyLib} from "../src/libraries/KeyLib.sol";

contract MinimalDelegationTest is DelegationHandler {
    using KeyLib for Key;

    error KeyDoesNotExist();

    function setUp() public {
        setUpDelegation();
    }

    function test_authorize() public {
        bytes32 keyHash = mockSecp256k1Key.hash();

        minimalDelegation.authorize(mockSecp256k1Key);

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, 0);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, abi.encodePacked(mockSecp256k1PublicKey));
    }

    function test_revoke() public {
        // first authorize the key
        bytes32 keyHash = minimalDelegation.authorize(mockSecp256k1Key);

        // then revoke the key
        minimalDelegation.revoke(keyHash);

        // then expect the key to not exist
        vm.expectRevert(KeyDoesNotExist.selector);
        minimalDelegation.getKey(keyHash);
    }
}

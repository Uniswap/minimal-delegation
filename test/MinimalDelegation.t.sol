// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {BaseTest} from "./BaseTest.t.sol";
import {Key, KeyType, KeyLib} from "../src/lib/KeyLib.sol";

contract MinimalDelegationTest is BaseTest {
    using KeyLib for Key;

    error KeyDoesNotExist();

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
        bytes32 keyHash = mockSecp256k1Key.hash();

        minimalDelegation.revoke(keyHash);

        vm.expectRevert(KeyDoesNotExist.selector);
        minimalDelegation.getKey(keyHash);
    }
}

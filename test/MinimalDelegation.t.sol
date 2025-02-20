// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {BaseTest} from "./BaseTest.t.sol";
import {Key, KeyType, KeyLib} from "../src/lib/KeyLib.sol";

contract MinimalDelegationTest is BaseTest {
    using KeyLib for Key;

    function test_authorize() public {
        address publicKey = vm.addr(0xdeadbeef);
        bytes memory encodedPublicKey = abi.encodePacked(publicKey);
        Key memory key = Key(type(uint40).max, KeyType.Secp256k1, true, encodedPublicKey);
        bytes32 keyHash = key.hash();
        minimalDelegation.authorize(key);

        Key memory fetchedKey = minimalDelegation.getKey(keyHash);
        assertEq(fetchedKey.expiry, type(uint40).max);
        assertEq(uint256(fetchedKey.keyType), uint256(KeyType.Secp256k1));
        assertEq(fetchedKey.isSuperAdmin, true);
        assertEq(fetchedKey.publicKey, encodedPublicKey);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {KeyType, Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {MockKeyLib} from "../utils/MockKeyLib.sol";

contract KeyLibTest is Test {
    using KeyLib for Key;

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
}

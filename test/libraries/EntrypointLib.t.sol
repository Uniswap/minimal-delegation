// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {EntrypointLib} from "../../src/libraries/EntrypointLib.sol";

contract EntrypointLibTest is Test {
    uint256 internal constant ENTRY_POINT_OVERRIDDEN = 1 << 255;

    function test_pack_fuzz(address entrypoint) public pure {
        uint256 packed = EntrypointLib.pack(entrypoint);
        assertEq(packed, uint256(uint160(entrypoint)) | ENTRY_POINT_OVERRIDDEN);
    }

    function test_unpack_fuzz(uint256 packed) public pure {
        address entrypoint = EntrypointLib.unpack(packed);
        assertEq(entrypoint, address(uint160(packed & ~ENTRY_POINT_OVERRIDDEN)));
    }

    function test_isOverriden_fuzz(uint256 packed) public pure {
        bool isOverriden = EntrypointLib.isOverriden(packed);
        assertEq(isOverriden, packed & ENTRY_POINT_OVERRIDDEN != 0);
    }
}

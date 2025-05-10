// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MockPrefixedSaltLib} from "../utils/MockPrefixedSaltLib.sol";

contract PrefixedSaltLibTest is Test {
    uint160 constant MASK_20_BYTES = uint160(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);

    MockPrefixedSaltLib mockPrefixedSaltLib;

    function setUp() public {
        mockPrefixedSaltLib = new MockPrefixedSaltLib();
    }

    function test_pack_unpack_fuzz(uint96 _prefix, address _implementation) public {
        bytes32 prefixedSalt = mockPrefixedSaltLib.pack(_prefix, _implementation);

        (uint96 prefix, address implementation) = mockPrefixedSaltLib.unpack(prefixedSalt);
        assertEq(prefix, _prefix);
        assertEq(implementation, _implementation);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TransientNativeAllowance} from "../../src/libraries/TransientNativeAllowance.sol";

/// @notice Simple tests for the TransientAllowance library
contract TransientNativeAllowanceTest is Test {
    function test_get_uninitialized(address spender) public {
        assertEq(TransientNativeAllowance.get(spender), 0);
    }

    function test_set_get_fuzz(address spender, uint256 allowance) public {
        TransientNativeAllowance.set(spender, allowance);
        assertEq(TransientNativeAllowance.get(spender), allowance);
    }
}

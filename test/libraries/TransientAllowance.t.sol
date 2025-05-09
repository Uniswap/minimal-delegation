// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TransientAllowance} from "../../src/libraries/TransientAllowance.sol";

/// @notice Simple tests for the TransientAllowance library
contract TransientAllowanceTest is Test {
    function test_get_uninitialized(address spender) public {
        assertEq(TransientAllowance.get(spender), 0);
    }

    function test_set_get_fuzz(address spender, uint256 allowance) public {
        TransientAllowance.set(spender, allowance);
        assertEq(TransientAllowance.get(spender), allowance);
    }
}

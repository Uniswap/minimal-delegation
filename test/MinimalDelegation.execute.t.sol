// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {Calls} from "../src/interfaces/IERC7821.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";

contract MinimalDelegationExecuteTest is TokenHandler, DelegationHandler {
    using CallBuilder for Calls[];

    bytes32 constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;

    address receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        tokenA.mint(address(minimalDelegation), 100e18);
        tokenB.mint(address(minimalDelegation), 100e18);
    }

    function test_execute_fuzz_reverts(bytes32 mode) public {
        if (mode != BATCHED_CALL) {
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
            minimalDelegation.execute(mode, "");
        }
    }

    function test_execute() public {
        Calls[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        assertEq(tokenA.balanceOf(address(minimalDelegation)), 100e18);
        assertEq(tokenB.balanceOf(address(minimalDelegation)), 100e18);

        vm.prank(address(minimalDelegation));
        minimalDelegation.execute(BATCHED_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(tokenB.balanceOf(address(receiver)), 1e18);
    }
}

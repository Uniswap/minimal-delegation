// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {Calls} from "../src/interfaces/IERC7821.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IERC20Errors} from "openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";

contract MinimalDelegationExecuteTest is TokenHandler, DelegationHandler {
    using CallBuilder for Calls[];

    bytes32 constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CAN_REVERT_CALL = 0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CALL_SUPPORTS_OPDATA = 0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;

    address receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        vm.deal(address(minimalDelegation), 100e18);
        tokenA.mint(address(minimalDelegation), 100e18);
        tokenB.mint(address(minimalDelegation), 100e18);
    }

    function test_execute_reverts_withUnsupportedExecutionMode() public {
        // Test specific modes since the fuzz is just over the first 2 bytes.
        bytes32[] memory modes = new bytes32[](3);
        bytes32 invalid_mode_1 = 0x0101100000000000000000000000000000000000000000000000000000000000;
        bytes32 invalid_mode_2 = 0x0100000000000a00000000000000000000000000000000000000000000000000;
        bytes32 invalid_mode_3 = 0x010100000000000000000000000000000000000000000000000000000000000a;
        modes[0] = invalid_mode_1;
        modes[1] = invalid_mode_2;
        modes[2] = invalid_mode_3;

        vm.startPrank(address(minimalDelegation));
        for (uint256 i = 0; i < modes.length; i++) {
            bytes32 mode = modes[i];
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
            minimalDelegation.execute(mode, abi.encode(CallBuilder.init()));
        }
    }

    function test_execute_fuzz_reverts(uint16 _mode) public {
        uint256 zeros = uint256(0);
        bytes32 mode = bytes32(uint256(_mode) << 240 | zeros);
        vm.startPrank(address(minimalDelegation));
        if (mode != BATCHED_CALL && mode != BATCHED_CAN_REVERT_CALL) {
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
        }
        minimalDelegation.execute(mode, abi.encode(CallBuilder.init()));
    }

    function test_execute_auth_reverts() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        minimalDelegation.execute(BATCHED_CALL, abi.encode(CallBuilder.init()));
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

        uint256 nativeBalanceBefore = address(minimalDelegation).balance;
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(tokenB.balanceOf(address(receiver)), 1e18);
        // native balance should not change
        assertEq(address(minimalDelegation).balance, nativeBalanceBefore);
    }

    function test_execute_native() public {
        Calls[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(minimalDelegation));
        minimalDelegation.execute(BATCHED_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(address(receiver).balance, 1e18);
    }

    function test_execute_batch_reverts() public {
        Calls[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call should cause the entire batch to revert
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.startPrank(address(minimalDelegation));
        bytes memory balanceError = abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientBalance.selector, address(minimalDelegation), 100e18, 101e18
        );
        vm.expectRevert(abi.encodeWithSelector(IERC7821.CallFailed.selector, balanceError));
        minimalDelegation.execute(BATCHED_CALL, executionData);
    }

    function test_execute_batch_canRevert_succeeds() public {
        Calls[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call reverts but the batch should succeed
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.startPrank(address(minimalDelegation));
        minimalDelegation.execute(BATCHED_CAN_REVERT_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        // the second transfer failed
        assertEq(tokenB.balanceOf(address(receiver)), 0);
    }

    function test_execute_batch_opData_reverts_notImplemented() public {
        Calls[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls, "");

        vm.startPrank(address(minimalDelegation));
        vm.expectRevert();
        minimalDelegation.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
    }
}

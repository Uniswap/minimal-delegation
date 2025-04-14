// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {MockHook} from "./MockHook.sol";

abstract contract HookHandler is Test {
    MockHook internal mockHook;
    MockHook internal mockValidationHook;
    MockHook internal mockExecutionHook;

    /// 0x1111 ... 1111
    address payable constant ALL_HOOKS = payable(0xf00000000000000000000000000000000000000f);
    /// 0x1111 ... 0111
    address payable constant ALL_VALIDATION_HOOKS = payable(0xF000000000000000000000000000000000000007);
    /// 0x1111 ...11000
    address payable constant ALL_EXECUTION_HOOKS = payable(0xF000000000000000000000000000000000000018);

    bytes constant EMPTY_HOOK_DATA = "";

    function setUpHooks() public {
        MockHook impl = new MockHook();
        vm.etch(ALL_HOOKS, address(impl).code);
        vm.etch(ALL_VALIDATION_HOOKS, address(impl).code);
        vm.etch(ALL_EXECUTION_HOOKS, address(impl).code);

        mockHook = MockHook(ALL_HOOKS);
        mockValidationHook = MockHook(ALL_VALIDATION_HOOKS);
        mockExecutionHook = MockHook(ALL_EXECUTION_HOOKS);

        vm.label(ALL_HOOKS, "AllMockHook");
        vm.label(ALL_VALIDATION_HOOKS, "ValidationMockHook");
        vm.label(ALL_EXECUTION_HOOKS, "ExecutionMockHook");
    }
}

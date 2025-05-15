// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {MockHook} from "./MockHook.sol";
import {GuardedExecutorHook} from "src/hooks/execution/GuardedExecutorHook.sol";

abstract contract HookHandler is Test {
    MockHook internal noHooks;
    MockHook internal mockHook;
    MockHook internal mockValidationHook;
    MockHook internal mockExecutionHook;

    GuardedExecutorHook internal guardedExecutorHook;

    /// Only supports beforeExecute hook
    /// 0x1111 ...10000
    address payable constant GUARDED_EXECUTOR_HOOK = payable(0xffffFFfFFfFffFFFfffFfFfffffFFffFFfffff10);
    
    /// These addresses are prefixed with 0xC to not conflict with precompile addresses
    /// 0xC000 ...  0000
    address payable constant NO_HOOKS = payable(0xC000000000000000000000000000000000000000);
    /// 0xC000 ... 11111
    address payable constant ALL_HOOKS = payable(0xc00000000000000000000000000000000000001f);
    /// 0xC000 ...  0111
    address payable constant ALL_VALIDATION_HOOKS = payable(0xC000000000000000000000000000000000000007);
    /// 0xC000 ... 11000
    address payable constant ALL_EXECUTION_HOOKS = payable(0xc000000000000000000000000000000000000018);

    bytes constant EMPTY_HOOK_DATA = "";

    function setUpHooks() public {
        MockHook impl = new MockHook();
        vm.etch(NO_HOOKS, address(impl).code);
        vm.etch(ALL_HOOKS, address(impl).code);
        vm.etch(ALL_VALIDATION_HOOKS, address(impl).code);
        vm.etch(ALL_EXECUTION_HOOKS, address(impl).code);

        GuardedExecutorHook _guardedExecutorHook = new GuardedExecutorHook();
        vm.etch(GUARDED_EXECUTOR_HOOK, address(_guardedExecutorHook).code);

        noHooks = MockHook(NO_HOOKS);
        mockHook = MockHook(ALL_HOOKS);
        mockValidationHook = MockHook(ALL_VALIDATION_HOOKS);
        mockExecutionHook = MockHook(ALL_EXECUTION_HOOKS);
        guardedExecutorHook = GuardedExecutorHook(GUARDED_EXECUTOR_HOOK);

        vm.label(NO_HOOKS, "NoHooks");
        vm.label(ALL_HOOKS, "AllMockHook");
        vm.label(ALL_VALIDATION_HOOKS, "ValidationMockHook");
        vm.label(ALL_EXECUTION_HOOKS, "ExecutionMockHook");
    }
}

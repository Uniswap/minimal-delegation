// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {MockHook} from "./MockHook.sol";

abstract contract HookHandler is Test {
    MockHook internal mockHook;

    /// 0x1111 ... 1111
    address payable constant ALL_HOOKS = payable(0xf00000000000000000000000000000000000000f);

    function setUpHooks() public {
        MockHook impl = new MockHook();
        vm.etch(ALL_HOOKS, address(impl).code);
        mockHook = MockHook(ALL_HOOKS);
        vm.label(ALL_HOOKS, "MockHook");
    }
}

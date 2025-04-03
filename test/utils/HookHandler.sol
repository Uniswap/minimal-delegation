// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {MockValidationHook} from "./MockValidationHook.sol";

abstract contract HookHandler is Test {
    MockValidationHook internal mockValidationHook;

    /// 0x1111 ... 1111
    address payable constant ALL_HOOKS = payable(0xf00000000000000000000000000000000000000f);

    function setUpHooks() public {
        MockValidationHook impl = new MockValidationHook();
        vm.etch(ALL_HOOKS, address(impl).code);
        mockValidationHook = MockValidationHook(ALL_HOOKS);
        vm.label(ALL_HOOKS, "MockValidationHook");
    }
}

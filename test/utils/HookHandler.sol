// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {MockValidationHook} from "./MockValidationHook.sol";

abstract contract HookHandler is Test {
    MockValidationHook internal mockValidationHook;

    /// 0x000... 1111
    address payable constant ALL_HOOKS = payable(0x000000000000000000000000000000000000000F);

    function setUpHooks() public {
        MockValidationHook impl = new MockValidationHook();
        vm.etch(ALL_HOOKS, address(impl).code);
        mockValidationHook = MockValidationHook(ALL_HOOKS);
    }
}

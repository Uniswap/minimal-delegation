// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IHook} from "../../src/interfaces/IHook.sol";
import {IValidationHook} from "../../src/interfaces/IValidationHook.sol";
import {HooksLib} from "../../src/libraries/HooksLib.sol";
import {HookHandler} from "../utils/HookHandler.sol";

contract HooksLibTest is HookHandler {
    using HooksLib for IHook;

    /// @notice Internal constant hook flags
    uint160 internal constant AFTER_VERIFY_SIGNATURE_FLAG = 1 << 0;
    uint160 internal constant AFTER_VALIDATE_USER_OP_FLAG = 1 << 1;
    uint160 internal constant AFTER_IS_VALID_SIGNATURE_FLAG = 1 << 2;
    uint160 internal constant BEFORE_EXECUTE_FLAG = 1 << 3;
    uint160 internal constant AFTER_EXECUTE_FLAG = 1 << 4;

    PackedUserOperation public mockUserOp;

    function setUp() public {
        setUpHooks();
    }

    /// @notice Fixtures help constrain the fuzzing to a specific set of flags
    /// @dev However, some portion of the fuzz tests will still run with edge cases and other values
    function fixtureFlag() public view returns (uint160[] memory) {
        uint160[] memory flags = new uint160[](5);
        flags[0] = AFTER_VERIFY_SIGNATURE_FLAG;
        flags[1] = AFTER_VALIDATE_USER_OP_FLAG;
        flags[2] = AFTER_IS_VALID_SIGNATURE_FLAG;
        flags[3] = BEFORE_EXECUTE_FLAG;
        flags[4] = AFTER_EXECUTE_FLAG;
        return flags;
    }

    function test_hasPermission_fuzz(IHook hook, uint160 flag) public view {
        if (uint160(address(hook)) & flag != 0) {
            assertEq(hook.hasPermission(flag), true);
        } else {
            assertEq(hook.hasPermission(flag), false);
        }
    }

    function test_handleAfterValidateUserOp() public view {
        bytes memory hookData = bytes("");
        vm.expectCall(address(noHooks), abi.encodeWithSelector(IValidationHook.afterValidateUserOp.selector, bytes32(0), mockUserOp, bytes32(0), hookData));
        HooksLib.handleAfterValidateUserOp(noHooks, bytes32(0), mockUserOp, bytes32(0), hookData);
    }
}

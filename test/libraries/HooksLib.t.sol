// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IHook} from "../../src/interfaces/IHook.sol";
import {IValidationHook} from "../../src/interfaces/IValidationHook.sol";
import {IExecutionHook} from "../../src/interfaces/IExecutionHook.sol";
import {HooksLib} from "../../src/libraries/HooksLib.sol";
import {HookHandler} from "../utils/HookHandler.sol";
import {MockHooksLib} from "../utils/MockHooksLib.sol";

contract HooksLibTest is HookHandler {
    using HooksLib for IHook;

    MockHooksLib internal mockHooksLib;

    /// @notice Internal constant hook flags
    uint160 internal constant AFTER_VERIFY_SIGNATURE_FLAG = 1 << 0;
    uint160 internal constant AFTER_VALIDATE_USER_OP_FLAG = 1 << 1;
    uint160 internal constant AFTER_IS_VALID_SIGNATURE_FLAG = 1 << 2;
    uint160 internal constant BEFORE_EXECUTE_FLAG = 1 << 3;
    uint160 internal constant AFTER_EXECUTE_FLAG = 1 << 4;

    PackedUserOperation public mockUserOp;

    function setUp() public {
        setUpHooks();
        mockHooksLib = new MockHooksLib();
    }

    /// @notice Fixtures help constrain the fuzzing to a specific set of flags
    /// @dev However, some portion of the fuzz tests will still run with edge cases and other values
    function fixtureFlag() public pure returns (uint160[] memory) {
        uint160[] memory flags = new uint160[](5);
        flags[0] = AFTER_VERIFY_SIGNATURE_FLAG;
        flags[1] = AFTER_VALIDATE_USER_OP_FLAG;
        flags[2] = AFTER_IS_VALID_SIGNATURE_FLAG;
        flags[3] = BEFORE_EXECUTE_FLAG;
        flags[4] = AFTER_EXECUTE_FLAG;
        return flags;
    }

    function test_hasPermission_fuzz(IHook hook, uint160 flag) public pure {
        if (uint160(address(hook)) & flag != 0) {
            assertEq(hook.hasPermission(flag), true);
        } else {
            assertEq(hook.hasPermission(flag), false);
        }
    }

    function test_handleAfterValidateUserOp_hasPermission_suceeds() public {
        // Ensure the hook does not revert
        mockHook.setValidateUserOpReturnValue(true);
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(
                IValidationHook.afterValidateUserOp.selector, bytes32(0), mockUserOp, bytes32(0), 0, bytes("")
            )
        );
        mockHooksLib.handleAfterValidateUserOp(mockHook, bytes32(0), mockUserOp, bytes32(0), 0, bytes(""));
    }

    function test_handleAfterValidateUserOp_hasPermission_reverts() public {
        // Ensure the hook reverts
        mockHook.setValidateUserOpReturnValue(false);
        vm.expectRevert();
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(
                IValidationHook.afterValidateUserOp.selector, bytes32(0), mockUserOp, bytes32(0), 0, bytes("")
            )
        );
        mockHooksLib.handleAfterValidateUserOp(mockHook, bytes32(0), mockUserOp, bytes32(0), 0, bytes(""));
    }

    function test_handleAfterValidateUserOp_noPermission_doesNotCallHook() public {
        // Set the hook to revert but do not expect a revert since it should not be called
        mockHook.setValidateUserOpReturnValue(false);
        mockHooksLib.handleAfterValidateUserOp(noHooks, bytes32(0), mockUserOp, bytes32(0), 0, bytes(""));
    }

    function test_handleIsValidSignature_hasPermission_suceeds() public {
        // Ensure the hook does not revert
        mockHook.setIsValidSignatureReturnValue(true);
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IValidationHook.afterIsValidSignature.selector, bytes32(0), bytes32(0), bytes(""))
        );
        mockHooksLib.handleAfterIsValidSignature(mockHook, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleIsValidSignature_hasPermission_reverts() public {
        // Ensure the hook reverts
        mockHook.setIsValidSignatureReturnValue(false);
        vm.expectRevert();
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IValidationHook.afterIsValidSignature.selector, bytes32(0), bytes32(0), bytes(""))
        );
        mockHooksLib.handleAfterIsValidSignature(mockHook, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleIsValidSignature_noPermission_doesNotCallHook() public {
        // Set the hook to revert but do not expect a revert since it should not be called
        mockHook.setIsValidSignatureReturnValue(false);
        mockHooksLib.handleAfterIsValidSignature(noHooks, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleVerifySignature_hasPermission_suceeds() public {
        // Ensure the hook does not revert
        mockHook.setVerifySignatureReturnValue(true);
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IValidationHook.afterVerifySignature.selector, bytes32(0), bytes32(0), bytes(""))
        );
        mockHooksLib.handleAfterVerifySignature(mockHook, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleVerifySignature_hasPermission_reverts() public {
        // Ensure the hook reverts
        mockHook.setVerifySignatureReturnValue(false);
        vm.expectRevert();
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IValidationHook.afterVerifySignature.selector, bytes32(0), bytes32(0), bytes(""))
        );
        mockHooksLib.handleAfterVerifySignature(mockHook, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleVerifySignature_noPermission_doesNotCallHook() public {
        // Set the hook to revert but do not expect a revert since it should not be called
        mockHook.setVerifySignatureReturnValue(false);
        mockHooksLib.handleAfterVerifySignature(noHooks, bytes32(0), bytes32(0), bytes(""));
    }

    function test_handleBeforeExecute_hasPermission_suceeds() public {
        // Ensure the hook does not revert
        mockHook.setBeforeExecuteRevertData(bytes(""));
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IExecutionHook.beforeExecute.selector, bytes32(0), address(0), 0, bytes(""))
        );
        mockHooksLib.handleBeforeExecute(mockHook, bytes32(0), address(0), 0, bytes(""));
    }

    function test_handleBeforeExecute_hasPermission_reverts() public {
        // Ensure the hook reverts
        mockHook.setBeforeExecuteRevertData(bytes("revert"));
        vm.expectRevert();
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IExecutionHook.beforeExecute.selector, bytes32(0), address(0), 0, bytes(""))
        );
        mockHooksLib.handleBeforeExecute(mockHook, bytes32(0), address(0), 0, bytes(""));
    }

    function test_handleBeforeExecute_noPermission_doesNotCallHook() public {
        // Set the hook to revert but do not expect a revert since it should not be called
        noHooks.setBeforeExecuteRevertData(bytes("revert"));
        mockHooksLib.handleBeforeExecute(noHooks, bytes32(0), address(0), 0, bytes(""));
    }

    function test_handleAfterExecute_hasPermission_suceeds() public {
        // Ensure the hook does not revert
        mockHook.setAfterExecuteRevertData(bytes(""));
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IExecutionHook.afterExecute.selector, bytes32(0), true, bytes(""), bytes(""))
        );
        mockHooksLib.handleAfterExecute(mockHook, bytes32(0), true, bytes(""), bytes(""));
    }

    function test_handleAfterExecute_hasPermission_reverts() public {
        // Ensure the hook reverts
        mockHook.setAfterExecuteRevertData(bytes("revert"));
        vm.expectRevert();
        vm.expectCall(
            address(mockHook),
            abi.encodeWithSelector(IExecutionHook.afterExecute.selector, bytes32(0), true, bytes(""), bytes(""))
        );
        mockHooksLib.handleAfterExecute(mockHook, bytes32(0), true, bytes(""), bytes(""));
    }

    function test_handleAfterExecute_noPermission_doesNotCallHook() public {
        // Set the hook to revert but do not expect a revert since it should not be called
        noHooks.setAfterExecuteRevertData(bytes("revert"));
        mockHooksLib.handleAfterExecute(noHooks, bytes32(0), true, bytes(""), bytes(""));
    }
}

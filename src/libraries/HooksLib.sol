// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IHook} from "../interfaces/IHook.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @author Inspired by https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol
library HooksLib {
    uint160 internal constant VERIFY_SIGNATURE_FLAG = 1 << 0;
    uint160 internal constant VALIDATE_USER_OP_FLAG = 1 << 1;
    uint160 internal constant IS_VALID_SIGNATURE_FLAG = 1 << 2;
    uint160 internal constant BEFORE_EXECUTE_FLAG = 1 << 3;
    uint160 internal constant AFTER_EXECUTE_FLAG = 1 << 4;

    error InvalidHookResponse();

    function hasPermission(IHook self, uint160 flag) internal pure returns (bool) {
        return uint160(address(self)) & flag != 0;
    }

    function validateUserOp(IHook self, bytes32 keyHash, PackedUserOperation memory userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes4 hookSelector;
        (hookSelector, validationData) = self.overrideValidateUserOp(keyHash, userOp, userOpHash);
        if (hookSelector != IValidationHook.overrideValidateUserOp.selector) revert InvalidHookResponse();
        return validationData;
    }

    function isValidSignature(IHook self, bytes32 keyHash, bytes32 data, bytes memory signature)
        internal
        view
        returns (bytes4 result)
    {
        bytes4 hookSelector;
        (hookSelector, result) = self.overrideIsValidSignature(keyHash, data, signature);
        if (hookSelector != IValidationHook.overrideIsValidSignature.selector) revert InvalidHookResponse();
        return result;
    }

    function verifySignature(IHook self, bytes32 keyHash, bytes32 data, bytes memory signature)
        internal
        view
        returns (bool result)
    {
        bytes4 hookSelector;
        (hookSelector, result) = self.overrideVerifySignature(keyHash, data, signature);
        if (hookSelector != IValidationHook.overrideVerifySignature.selector) revert InvalidHookResponse();
        return result;
    }

    function handleBeforeExecute(IHook self, bytes32 keyHash, address to, uint256 value, bytes memory data)
        internal
        returns (bytes memory result)
    {
        bytes4 hookSelector;
        (hookSelector, result) = self.beforeExecute(keyHash, to, value, data);
        if (hookSelector != IExecutionHook.beforeExecute.selector) revert InvalidHookResponse();
        return result;
    }

    function handleAfterExecute(IHook self, bytes32 keyHash, bytes memory beforeExecuteData) internal {
        bytes4 hookSelector = self.afterExecute(keyHash, beforeExecuteData);
        if (hookSelector != IExecutionHook.afterExecute.selector) revert InvalidHookResponse();
    }
}

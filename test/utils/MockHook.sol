// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";
import {IHook} from "src/interfaces/IHook.sol";
import {IValidationHook} from "src/interfaces/IValidationHook.sol";
import {IExecutionHook} from "src/interfaces/IExecutionHook.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockHook is IHook {
    bool internal _verifySignatureReturnValue;
    bool internal _isValidSignatureReturnValue;
    bool internal _validateUserOpReturnValue;
    bytes internal _beforeExecuteReturnValue;
    bytes internal _beforeExecuteRevertData;

    function setVerifySignatureReturnValue(bool returnValue) external {
        _verifySignatureReturnValue = returnValue;
    }

    function setIsValidSignatureReturnValue(bool returnValue) external {
        _isValidSignatureReturnValue = returnValue;
    }

    function setValidateUserOpReturnValue(bool isValid) external {
        _validateUserOpReturnValue = isValid;
    }

    function setBeforeExecuteReturnValue(bytes memory returnValue) external {
        _beforeExecuteReturnValue = returnValue;
    }

    function setBeforeExecuteRevertData(bytes memory revertData) external {
        _beforeExecuteRevertData = revertData;
    }

    function afterValidateUserOp(bytes32, PackedUserOperation calldata, bytes32, bytes calldata)
        external
        view
        returns (bytes4 selector)
    {
        if (_validateUserOpReturnValue) {
            return (IValidationHook.afterValidateUserOp.selector);
        } else {
            revert();
        }
    }

    function afterIsValidSignature(bytes32, bytes32, bytes calldata)
        external
        view
        returns (bytes4 selector)
    {
        if(_isValidSignatureReturnValue) {
            return IValidationHook.afterIsValidSignature.selector;
        } else {
            revert();
        }
    }

    function afterVerifySignature(bytes32, bytes32, bytes calldata) external view returns (bytes4 selector) {
        if(_verifySignatureReturnValue) {
            return IValidationHook.afterVerifySignature.selector;
        } else {
            revert();
        }
    }

    function beforeExecute(bytes32, address, uint256, bytes calldata) external view returns (bytes4, bytes memory) {
        if (_beforeExecuteRevertData.length > 0) {
            bytes memory revertData = abi.encode(_beforeExecuteRevertData);
            assembly {
                revert(add(revertData, 32), mload(revertData))
            }
        }
        return (IExecutionHook.beforeExecute.selector, _beforeExecuteReturnValue);
    }

    function afterExecute(bytes32, bytes calldata) external pure returns (bytes4) {
        return (IExecutionHook.afterExecute.selector);
    }
}

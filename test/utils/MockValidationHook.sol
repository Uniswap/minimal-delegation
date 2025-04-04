// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IHook} from "src/interfaces/IHook.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockValidationHook is IHook {
    bool internal _verifySignatureReturnValue;
    bytes4 internal _isValidSignatureReturnValue;
    uint256 internal _validateUserOpReturnValue;

    function setVerifySignatureReturnValue(bool returnValue) external {
        _verifySignatureReturnValue = returnValue;
    }

    function setIsValidSignatureReturnValue(bytes4 returnValue) external {
        _isValidSignatureReturnValue = returnValue;
    }

    function setValidateUserOpReturnValue(uint256 returnValue) external {
        _validateUserOpReturnValue = returnValue;
    }

    function overrideValidateUserOp(bytes32, PackedUserOperation calldata, bytes32)
        external
        view
        returns (bytes4, uint256)
    {
        return (IHook.overrideValidateUserOp.selector, _validateUserOpReturnValue);
    }

    function overrideIsValidSignature(bytes32, bytes32, bytes calldata) external view returns (bytes4, bytes4) {
        return (IHook.overrideIsValidSignature.selector, _isValidSignatureReturnValue);
    }

    function overrideVerifySignature(bytes32, bytes32, bytes calldata) external view returns (bool) {
        return _verifySignatureReturnValue;
    }
}

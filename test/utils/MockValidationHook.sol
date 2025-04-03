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

    function verifySignature(bytes32, bytes calldata) external view virtual returns (bool) {
        return _verifySignatureReturnValue;
    }

    function isValidSignature(bytes32, bytes calldata) external view virtual returns (bytes4) {
        return _isValidSignatureReturnValue;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external view virtual returns (uint256) {
        return _validateUserOpReturnValue;
    }
}

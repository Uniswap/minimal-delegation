// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title IValidationHook
/// @notice Hook interface for additional validation logic to be run after signature validation
interface IValidationHook {
    /// @dev Must revert if the user operation is invalid with `witness`
    /// @return bytes4 IValidationHook.afterValidateUserOp.selector
    function afterValidateUserOp(bytes32 keyHash, PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata witness)
        external
        view
        returns (bytes4);

    /// @dev Must revert if the key is not allowed to call isValidSignature with `witness`
    /// @return bytes4 IValidationHook.afterIsValidSignature.selector
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata witness)
        external
        view
        returns (bytes4);

    /// @dev Must revert if the signature is invalid with `witness`
    /// @return bytes4 IValidationHook.afterVerifySignature.selector
    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata witness)
        external
        view
        returns (bytes4);
}

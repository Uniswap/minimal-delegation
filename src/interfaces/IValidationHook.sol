// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title IValidationHook
/// @notice Hook interface for additional validation logic to be run after signature validation
interface IValidationHook {
    /// @dev Must revert if the user operation is invalid with `witness`
    /// @return selector Must be afterValidateUserOp.selector
    /// @return validationData The validation data to be returned, overriding the default value
    function afterValidateUserOp(bytes32 keyHash, PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata witness)
        external
        view
        returns (bytes4 selector, uint256 validationData);

    /// @dev Called to override isValidSignature result
    /// @return selector Must be afterIsValidSignature.selector
    /// @return The EIP-1271 magic value (or invalid value) to return
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata witness)
        external
        view
        returns (bytes4 selector, bytes4);

    /// @dev Must revert if the signature is invalid with `witness`
    /// @return selector Must be afterVerifySignature.selector
    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata witness)
        external
        view
        returns (bytes4 selector);
}

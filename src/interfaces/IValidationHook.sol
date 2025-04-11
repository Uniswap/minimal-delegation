// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title IValidationHook
/// @notice Hook interface for optional signature validation logic
interface IValidationHook {
    /// @notice Hook called after `validateUserOp` is called on the account by the entrypoint
    /// @return selector Must be afterValidateUserOp.selector
    /// @return validationData The validation data to be returned, overriding the validation done within the account
    function afterValidateUserOp(bytes32 keyHash, PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata hookData)
        external
        view
        returns (bytes4 selector, uint256 validationData);

    /// @notice Hook called after verifying a signature over a digest in an EIP-1271 callback
    /// @return selector Must be afterIsValidSignature.selector
    /// @return magicValue The EIP-1271 magic value (or invalid value) to return, overriding the validation done within the account
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        external
        view
        returns (bytes4 selector, bytes4 magicValue);

    /// @notice Hook called after verifying a signature over `SignedCalls`. MUST revert if the signature is invalid
    /// @return selector Must be afterVerifySignature.selector
    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData) external view returns (bytes4 selector);
}

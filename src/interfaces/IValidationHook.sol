// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title IValidationHook
/// @notice Hook interface for optional signature validation logic
/// @dev The keyHash is validated against the signature before each hook is called, but
///      the hookData is NOT signed over or validated within the account. It MUST be treated as unsafe and can be set by anybody.
interface IValidationHook {
    /// @notice Hook called after `validateUserOp` is called on the account by the entrypoint
    /// @param keyHash the key which signed over userOpHash
    /// @param userOp UserOperation
    /// @param userOpHash hash of the UserOperation
    /// @param hookData any data to be passed to the hook
    /// @return selector Must be afterValidateUserOp.selector
    /// @return validationData The validation data to be returned, overriding the validation done within the account
    function afterValidateUserOp(
        bytes32 keyHash,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata hookData
    ) external view returns (bytes4 selector, uint256 validationData);

    /// @notice Hook called after verifying a signature over a digest in an EIP-1271 callback
    /// @param keyHash the key which signed over digest
    /// @param digest the digest to verify
    /// @param hookData any data to be passed to the hook
    /// @return selector Must be afterIsValidSignature.selector
    /// @return magicValue The EIP-1271 magic value (or invalid value) to return, overriding the validation done within the account
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        external
        view
        returns (bytes4 selector, bytes4 magicValue);

    /// @notice Hook called after verifying a signature over `SignedBatchedCall`. MUST revert if the signature is invalid
    /// @param keyHash the key which signed over digest
    /// @param digest the digest to verify
    /// @param hookData any data to be passed to the hook
    /// @return selector Must be afterVerifySignature.selector
    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        external
        view
        returns (bytes4 selector);
}

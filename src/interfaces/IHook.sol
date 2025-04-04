// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IHook {
    /**
     * VALIDATION HOOKS
     */

    /// @notice Validates a user operation
    /// Does not require passing in missingAccountFunds like the IAccount interface
    function overrideValidateUserOp(bytes32 keyHash, PackedUserOperation calldata, bytes32)
        external
        view
        returns (bytes4, uint256);

    /// @notice Validates a signature over a digest and returns the ERC1271 return value
    function overrideIsValidSignature(bytes32 keyHash, bytes32 data, bytes calldata signature)
        external
        view
        returns (bytes4, bytes4);

    /// @notice Validates a signature over a digest and returns a boolean
    function overrideVerifySignature(bytes32 keyHash, bytes32 data, bytes calldata signature)
        external
        view
        returns (bytes4, bool);

    /**
     * EXECUTION HOOKS
     */

    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param to The address to call
    /// @param data TODO: The calldata sent. For `executeUserOp` calls of validation-associated hooks, hook modules
    /// should receive the full calldata.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function beforeExecute(bytes32 keyHash, address to, bytes calldata data) external returns (bytes memory);

    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param beforeExecuteData The context returned by the beforeExecute hook.
    function afterExecute(bytes32 keyHash, bytes calldata beforeExecuteData) external;
}

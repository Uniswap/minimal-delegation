// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @title IExecutionHook
/// @notice Hooks that are executed before and after a user operation is executed.
interface IExecutionHook {
    /// @dev Must revert if the entire call should revert.
    /// @param keyHash The key hash to check against
    /// @param to The address to call
    /// @param value value of the call
    /// @param data TODO: The calldata sent. For `executeUserOp` calls of validation-associated hooks, hook modules
    /// should receive the full calldata.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function beforeExecute(bytes32 keyHash, address to, uint256 value, bytes calldata data)
        external
        returns (bytes4, bytes memory);

    /// @dev Must revert if the entire call should revert.
    /// @param keyHash The key hash to check against
    /// @param beforeExecuteData The context returned by the beforeExecute hook.
    function afterExecute(bytes32 keyHash, bytes calldata beforeExecuteData) external returns (bytes4);
}

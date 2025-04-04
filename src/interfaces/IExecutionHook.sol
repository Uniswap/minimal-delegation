// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IExecutionHook {
    /**
     * EXECUTION HOOKS
     */

    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param to The address to call
    /// @param data TODO: The calldata sent. For `executeUserOp` calls of validation-associated hooks, hook modules
    /// should receive the full calldata.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function beforeExecute(bytes32 keyHash, address to, bytes calldata data) external returns (bytes4, bytes memory);

    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param beforeExecuteData The context returned by the beforeExecute hook.
    function afterExecute(bytes32 keyHash, bytes calldata beforeExecuteData) external returns (bytes4);
}

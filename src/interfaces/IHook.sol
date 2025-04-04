// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IHook {
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
     * Similar to https://eips.ethereum.org/EIPS/eip-6900
     */

    /// @notice Run the pre execution hook specified by the `keyHash`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param to The address to call
    /// @param data The calldata sent. For `executeUserOp` calls of validation-associated hooks, hook modules
    /// should receive the full calldata.
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preExecutionHook(bytes32 keyHash, address to, bytes calldata data) external returns (bytes memory);

    /// @notice Run the post execution hook specified by the `keyHash`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param keyHash The key hash to check against
    /// @param preExecHookData The context returned by its associated pre execution hook.
    function postExecutionHook(bytes32 keyHash, bytes calldata preExecHookData) external;
}

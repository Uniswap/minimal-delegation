// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IValidationHook {
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
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IValidator {
    /**
     * @dev Validates a UserOperation
     * @param userOp the ERC-4337 PackedUserOperation
     * @param userOpHash the hash of the ERC-4337 PackedUserOperation
     *
     * MUST validate that the signature is a valid signature of the userOpHash
     * SHOULD return ERC-4337's SIG_VALIDATION_FAILED (and not revert) on signature mismatch
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);

    /// @notice Verifies a signature over a digest
    function verifySignature(bytes32 digest, bytes calldata signature) external view returns (bool);
}

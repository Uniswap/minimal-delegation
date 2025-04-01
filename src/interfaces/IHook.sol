// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IHook {
    /// @notice From ERC1271
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);

    /// @notice From ERC4337
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256);

    /// @notice Verifies a signature over a digest
    function verifySignature(bytes32 digest, bytes calldata signature) external view returns (bool);
}

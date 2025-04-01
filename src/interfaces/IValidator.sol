// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

interface IValidator {
    /// @notice Verifies a signature over a digest
    function verifySignature(bytes32 digest, bytes calldata signature) external view returns (bool);
}

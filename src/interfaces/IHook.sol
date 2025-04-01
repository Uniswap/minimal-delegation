// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "./IERC1271.sol";

interface IHook is IERC1271 {
    /// @notice Validates a user operation
    /// Does not require passing in missingAccountFunds like the IAccount interface
    function validateUserOp(PackedUserOperation calldata, bytes32) external view returns (uint256);
}

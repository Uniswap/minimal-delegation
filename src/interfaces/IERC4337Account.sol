// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

/// @title IERC4337Account Interface
/// @dev Extends the IAccount interface from the ERC4337 specification
interface IERC4337Account is IAccount {
    /// Thrown when the caller to validateUserOp is not the EntryPoint contract
    error NotEntryPoint();
}

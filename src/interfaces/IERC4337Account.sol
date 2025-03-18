// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

/// @title IERC4337Account Interface
/// @notice Interface for contracts that support updating the EntryPoint contract
/// @dev Extends the IAccount interface from the ERC4337 specification
interface IERC4337Account is IAccount {
    error NotEntryPoint();

    /// @notice Emitted when the EntryPoint address is updated
    /// @param newEntryPoint The new EntryPoint address
    event EntryPointUpdated(address indexed newEntryPoint);

    function updateEntryPoint(address entryPoint) external;

    /// @notice Returns the address of the EntryPoint contract that this account uses
    /// @return The address of the EntryPoint contract
    function ENTRY_POINT() external view returns (address);
}

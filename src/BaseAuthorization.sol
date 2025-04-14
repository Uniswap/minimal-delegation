// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @title BaseAuthorization
/// @notice A base contract that provides a modifier to restrict access to the contract itself
contract BaseAuthorization {
    /// @notice An error that is thrown when an unauthorized address attempts to call a function
    error Unauthorized();

    /// @notice A modifier that restricts access to the contract itself
    modifier onlyThis() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }
}

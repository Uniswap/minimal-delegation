// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @title BaseAuthorization
/// @notice A base contract that provides a modifier to restrict access to the contract itself
abstract contract BaseAuthorization {
    /// @notice An error that is thrown when an unauthorized address attempts to call a function
    error Unauthorized();

    function isAuthorizedAdmin(address toAuthorize) public view virtual returns (bool);

    /// @notice A modifier that restricts access to the contract itself
    modifier onlyAdmin() {
        address caller = msg.sender;
        /// If the caller is not the root admin key, check if the caller has been authorized as another admin key.
        if (caller != address(this)) {
            if (!isAuthorizedAdmin(caller)) revert Unauthorized();
        }

        _;
    }
}

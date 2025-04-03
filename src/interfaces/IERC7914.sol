// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @title IERC7914
interface IERC7914 {
    /// @notice Thrown when the caller's allowance is exceeded when transferring
    error AllowanceExceeded();
    /// @notice Thrown when the caller is not an approved spender
    error IncorrectSpender();
    /// @notice Thrown when the transfer of native tokens fails
    error TransferNativeFailed();

    /// @notice Emitted when a transfer from native is made
    event TransferFromNative(address indexed from, address indexed to, uint256 value);
    /// @notice Emitted when a native approval is made
    event ApproveNative(address indexed owner, address indexed spender, uint256 value);

    /// @notice Returns the allowance of a spender
    function allowance(address spender) external returns (uint256);

    /// @notice Transfers native tokens from the caller to a recipient
    function transferFromNative(address from, address recipient, uint256 amount) external returns (bool);

    /// @notice Approves a spender to transfer native tokens on behalf of the caller
    function approveNative(address spender, uint256 amount) external returns (bool);
}

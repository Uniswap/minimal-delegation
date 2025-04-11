// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

interface IERC7821 {
    /// @dev Thrown when an unsupported execution mode is provided.
    error UnsupportedExecutionMode();

    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 mode) external view returns (bool result);
}

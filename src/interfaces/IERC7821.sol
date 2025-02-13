// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IERC7821 {
    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 mode) external view returns (bool result);
}

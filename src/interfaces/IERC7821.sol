// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

struct Calls {
    address to;
    uint256 value;
    bytes data;
}

interface IERC7821 {
    error UnsupportedExecutionMode();
    error Unauthorized();
    error CallFailed();

    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 mode) external view returns (bool result);
}

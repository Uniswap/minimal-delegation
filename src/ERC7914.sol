// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "./interfaces/IERC7914.sol";

/// @title ERC-7914
/// @notice Abstract ERC-7914 implementation
abstract contract ERC7914 is IERC7914 {
    /// @inheritdoc IERC7914
    function allowance(address spender) external virtual returns (uint256);

    /// @inheritdoc IERC7914
    function approveNative(address spender, uint256 amount) external virtual returns (bool);

    /// @inheritdoc IERC7914
    function transferFromNative(address from, address recipient, uint256 amount) external virtual returns (bool);
}

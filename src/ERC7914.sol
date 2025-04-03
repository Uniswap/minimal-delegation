// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "./interfaces/IERC7914.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";

/// @title ERC-7914
/// @notice Abstract ERC-7914 implementation
abstract contract ERC7914 is IERC7914 {
    /// @dev Must be overridden by the implementation
    function _onlyThis() internal view virtual {}

    /// @inheritdoc IERC7914
    function allowance(address spender) external view override returns (uint256) {
        return MinimalDelegationStorageLib.get().allowance[spender];
    }

    /// @inheritdoc IERC7914
    function approveNative(address spender, uint256 amount) external override returns (bool) {
        _onlyThis();
        MinimalDelegationStorageLib.get().allowance[spender] = amount;
        emit ApproveNative(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNative(address from, address recipient, uint256 amount) public override returns (bool) {
        if (from != address(this)) revert IncorrectSpender();
        if (MinimalDelegationStorageLib.get().allowance[msg.sender] < amount) revert AllowanceExceeded();
        if (amount == 0) return false; // early return for amount == 0
        MinimalDelegationStorageLib.get().allowance[msg.sender] -= amount;
        (bool success,) = payable(recipient).call{value: amount}("");
        if (success) {
            emit TransferFromNative(address(this), recipient, amount);
            return true;
        }
        return false;
    }
}

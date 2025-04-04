// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "./interfaces/IERC7914.sol";
import {TransientAllowance} from "./libraries/TransientAllowance.sol";

/// @title ERC-7914
/// @notice Abstract ERC-7914 implementation
abstract contract ERC7914 is IERC7914 {
    mapping(address => uint256) public allowance;

    /// @dev Must be overridden by the implementation
    function _onlyThis() internal view virtual {}

    /// @inheritdoc IERC7914
    function transientAllowance(address spender) external view returns (uint256) {
        return TransientAllowance.getTransientAllowance(spender);
    }

    /// @inheritdoc IERC7914
    function approveNative(address spender, uint256 amount) external override returns (bool) {
        _onlyThis();
        allowance[spender] = amount;
        emit ApproveNative(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNative(address from, address recipient, uint256 amount) external override returns (bool) {
        if (from != address(this)) revert IncorrectSender();
        if (allowance[msg.sender] < amount) revert AllowanceExceeded();
        if (amount == 0) return false; // early return for amount == 0
        allowance[msg.sender] -= amount;
        (bool success,) = payable(recipient).call{value: amount}("");
        if (!success) {
            revert TransferNativeFailed();
        }
        emit TransferFromNative(address(this), recipient, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function approveNativeTransient(address spender, uint256 amount) external override returns (bool) {
        _onlyThis();
        TransientAllowance.setTransientAllowance(spender, amount);
        emit ApproveNativeTransient(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNativeTransient(address from, address recipient, uint256 amount)
        external
        override
        returns (bool)
    {
        if (from != address(this)) revert IncorrectSender();
        if (TransientAllowance.getTransientAllowance(msg.sender) < amount) revert AllowanceExceeded();
        if (amount == 0) return false; // early return for amount == 0
        TransientAllowance.setTransientAllowance(
            msg.sender, TransientAllowance.getTransientAllowance(msg.sender) - amount
        );
        (bool success,) = payable(recipient).call{value: amount}("");
        if (!success) {
            revert TransferNativeFailed();
        }
        emit TransferFromNativeTransient(address(this), recipient, amount);
        return true;
    }
}

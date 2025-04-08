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
    function transientAllowance(address spender) public view returns (uint256) {
        return TransientAllowance.get(spender);
    }

    /// @inheritdoc IERC7914
    function approveNative(address spender, uint256 amount) external override returns (bool) {
        _onlyThis();
        allowance[spender] = amount;
        emit ApproveNative(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function approveNativeTransient(address spender, uint256 amount) external override returns (bool) {
        _onlyThis();
        TransientAllowance.set(spender, amount);
        emit ApproveNativeTransient(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNative(address from, address recipient, uint256 amount) external override returns (bool) {
        return _transferFrom(from, recipient, amount, false);
    }

    /// @inheritdoc IERC7914
    function transferFromNativeTransient(address from, address recipient, uint256 amount)
        external
        override
        returns (bool)
    {
        return _transferFrom(from, recipient, amount, true);
    }

    /// @dev Internal function to validate and execute transfers
    /// @param from The address to transfer from
    /// @param recipient The address to receive the funds
    /// @param amount The amount to transfer
    /// @param isTransient Whether this is transient allowance or not
    /// @return success Whether the transfer was successful
    function _transferFrom(address from, address recipient, uint256 amount, bool isTransient) internal returns (bool) {
        // Validate inputs
        if (from != address(this)) revert IncorrectSender();
        if (amount == 0) return false;

        // Check allowance
        uint256 currentAllowance = isTransient ? transientAllowance(msg.sender) : allowance[msg.sender];
        if (currentAllowance < amount) revert AllowanceExceeded();

        // Update allowance before transfer to prevent reentrancy
        if (currentAllowance < type(uint256).max) {
            if (isTransient) {
                TransientAllowance.set(msg.sender, currentAllowance - amount);
            } else {
                allowance[msg.sender] -= amount;
            }
        }

        // Execute transfer
        (bool success,) = payable(recipient).call{value: amount}("");
        if (!success) {
            revert TransferNativeFailed();
        }

        // Emit appropriate event
        if (isTransient) {
            emit TransferFromNativeTransient(address(this), recipient, amount);
        } else {
            emit TransferFromNative(address(this), recipient, amount);
        }

        return true;
    }
}

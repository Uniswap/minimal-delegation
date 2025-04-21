// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC7914} from "./interfaces/IERC7914.sol";
import {TransientAllowance} from "./libraries/TransientAllowance.sol";
import {BaseAuthorization} from "./BaseAuthorization.sol";

/// @title ERC-7914
/// @notice Abstract ERC-7914 implementation
abstract contract ERC7914 is IERC7914, BaseAuthorization {
    mapping(address spender => uint256 allowance) public allowance;

    /// @inheritdoc IERC7914
    function approveNative(address spender, uint256 amount) external onlyThis returns (bool) {
        allowance[spender] = amount;
        emit ApproveNative(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function approveNativeTransient(address spender, uint256 amount) external onlyThis returns (bool) {
        TransientAllowance.set(spender, amount);
        emit ApproveNativeTransient(address(this), spender, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNative(address from, address recipient, uint256 amount) external returns (bool) {
        if (amount == 0) return true;
        _transferFrom(from, recipient, amount, false);
        emit TransferFromNative(address(this), recipient, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transferFromNativeTransient(address from, address recipient, uint256 amount) external returns (bool) {
        if (amount == 0) return true;
        _transferFrom(from, recipient, amount, true);
        emit TransferFromNativeTransient(address(this), recipient, amount);
        return true;
    }

    /// @inheritdoc IERC7914
    function transientAllowance(address spender) public view returns (uint256) {
        return TransientAllowance.get(spender);
    }

    /// @dev Internal function to validate and execute transfers
    /// @param from The address to transfer from
    /// @param recipient The address to receive the funds
    /// @param amount The amount to transfer
    /// @param isTransient Whether this is transient allowance or not
    function _transferFrom(address from, address recipient, uint256 amount, bool isTransient) internal {
        // Validate inputs
        if (from != address(this)) revert IncorrectSender();

        // Check allowance
        uint256 currentAllowance = isTransient ? transientAllowance(msg.sender) : allowance[msg.sender];
        if (currentAllowance < amount) revert AllowanceExceeded();

        // Update allowance
        if (currentAllowance < type(uint256).max) {
            uint256 newAllowance;
            unchecked {
                newAllowance = currentAllowance - amount;
            }
            if (isTransient) {
                TransientAllowance.set(msg.sender, newAllowance);
            } else {
                allowance[msg.sender] = newAllowance;
            }
        }

        // Execute transfer
        (bool success,) = payable(recipient).call{value: amount}("");
        if (!success) {
            revert TransferNativeFailed();
        }
    }
}

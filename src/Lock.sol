// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {Locker} from "./libraries/Locker.sol";

/// @title Lock
/// @notice A contract that provides a reentrancy lock for external calls
/// @author Modified from https://github.com/Uniswap/universal-router/blob/main/contracts/base/Lock.sol
contract Lock {
    /// @notice Thrown when attempting to reenter a locked function from an external caller
    error ContractLocked();

    /// @notice Modifier enforcing a reentrancy lock that allows self-reentrancy
    /// @dev If the contract is not locked, use msg.sender as the locker
    modifier isNotLocked() {
        address locker = _getLocker();
        // Set the lock if not set already
        if (locker != address(0)) {
            // Only allow self re-entracy within a lock
            if (msg.sender != address(this)) revert ContractLocked();
            _;
        } else {
            // Top level call, set the lock to the sender
            Locker.set(msg.sender);
            _;
            Locker.set(address(0));
        }
    }

    /// @notice return the current locker of the contract
    function _getLocker() internal view returns (address) {
        return Locker.get();
    }
}

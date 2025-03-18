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
        // Apply a reentrancy lock for all external callers
        if (msg.sender != address(this)) {
            if (Locker.isLocked()) revert ContractLocked();
            Locker.set(msg.sender);
            _;
            Locker.set(address(0));
        } else if (!Locker.isLocked()) {
            /// @dev For 7702 accounts the msg.sender is address(this) but we still need to set the lock if unset
            Locker.set(msg.sender);
            _;
            Locker.set(address(0));
        } else {
            // The contract is allowed to reenter itself
            _;
        }
    }

    /// @notice return the current locker of the contract
    function _getLocker() internal view returns (address) {
        return Locker.get();
    }
}

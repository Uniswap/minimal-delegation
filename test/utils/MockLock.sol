// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Lock} from "../../src/Lock.sol";

/// @notice Helper contract to test the Lock contract
contract MockLock is Lock {
    /// @notice Error thrown when the locker is not address(this)
    error LockerIsNotThis();

    function getLocker() public view returns (address) {
        return _getLocker();
    }

    /// @dev Original locker must be address(this)
    function lockerIsThis() public isNotLocked {
        if (getLocker() != address(this)) revert LockerIsNotThis();
    }

    /// @dev Unrestricted sender
    function lockerIsAnyone() public {}

    /// @dev Self re-entering function which sets the locker to msg.sender
    function selfCall(bytes memory data) external isNotLocked {
        (bool success, bytes memory result) = address(this).call(data);
        if (!success) {
            // bubble up revert
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

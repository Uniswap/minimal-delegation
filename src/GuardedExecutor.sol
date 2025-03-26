// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";

abstract contract GuardedExecutor {
    function _setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) external {
        _authorizeCaller();
        MinimalDelegationStorageLib.get().canExecute[keyHash].update(_packCanExecute(to, selector), can, 2048);
    }

    function canExecute(bytes32 keyHash, address to, bytes calldata data) external view returns (bool) {
        // EOA keyhash can execute any call.
        if (keyHash == bytes32(0)) return true;
        // TODO: implement this
        return false;
    }
}
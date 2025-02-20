// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {Key, KeyLib} from "./lib/KeyLib.sol";
import {MinimalDelegationStorageLib} from "./lib/MinimalDelegationStorageLib.sol";

contract MinimalDelegation {
    using KeyLib for Key;

    /// @dev The key does not exist.
    error KeyDoesNotExist();

    /// @dev Authorizes the `key`.
    function authorize(Key memory key) external returns (bytes32 keyHash) {
        keyHash = key.hash();
        MinimalDelegationStorageLib.get().keyStorage[keyHash] = abi.encode(key);
    }

    /// @dev Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function getKey(bytes32 keyHash) external view returns (Key memory key) {
        bytes memory data = MinimalDelegationStorageLib.get().keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }
}

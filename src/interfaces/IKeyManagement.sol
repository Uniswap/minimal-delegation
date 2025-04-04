// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Key} from "../libraries/KeyLib.sol";
import {IHook} from "./IHook.sol";
import {Settings} from "../libraries/SettingsLib.sol";

interface IKeyManagement {
    /// @dev Emitted when a key is registered.
    event Registered(bytes32 indexed keyHash, Key key);

    /// @dev Emitted when a key is revoked.
    event Revoked(bytes32 indexed keyHash);

    /// @dev The key does not exist.
    error KeyDoesNotExist();

    /// @dev Registers the `key`.
    function register(Key memory key) external;

    /// @dev Revokes the key with the `keyHash`.
    function revoke(bytes32 keyHash) external;

    /// @dev Updates the `keyHash` with the `keySettings`.
    function update(bytes32 keyHash, Settings keySettings) external;

    /// @dev Returns the number of registered keys.
    function keyCount() external view returns (uint256);

    /// @dev Returns the key at the `i`-th position in the key list.
    function keyAt(uint256 i) external view returns (Key memory);

    /// @dev Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function getKey(bytes32 keyHash) external view returns (Key memory key);

    /// @dev Returns the settings for the `keyHash`.
    function getKeySettings(bytes32 keyHash) external view returns (Settings);
}

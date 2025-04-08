// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";
import {Settings, SettingsLib} from "./libraries/SettingsLib.sol";

/// @dev A base contract for managing keys
abstract contract KeyManagement is IKeyManagement {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;

    EnumerableSetLib.Bytes32Set keyHashes;
    mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
    mapping(bytes32 keyHash => Settings settings) keySettings;

    /// @dev Must be overridden by the implementation
    function _onlyThis() internal view virtual {}

    /// @inheritdoc IKeyManagement
    function register(Key memory key) external {
        _onlyThis();

        if (key.isRootKey()) revert CannotRegisterSelf();

        bytes32 keyHash = key.hash();
        keyStorage[keyHash] = abi.encode(key);
        keyHashes.add(keyHash);

        emit Registered(keyHash, key);
    }

    function update(bytes32 keyHash, Settings settings) external {
        _onlyThis();
        if (keyHash == KeyLib.ROOT_KEY_HASH) revert CannotUpdateRootKey();
        if (!keyHashes.contains(keyHash)) revert KeyDoesNotExist();
        keySettings[keyHash] = settings;
    }

    /// @inheritdoc IKeyManagement
    function revoke(bytes32 keyHash) external {
        _onlyThis();

        if (!keyHashes.remove(keyHash)) revert KeyDoesNotExist();
        delete keyStorage[keyHash];
        keySettings[keyHash] = SettingsLib.DEFAULT;

        emit Revoked(keyHash);
    }

    /// @inheritdoc IKeyManagement
    function keyCount() external view returns (uint256) {
        return keyHashes.length();
    }

    /// @inheritdoc IKeyManagement
    function keyAt(uint256 i) external view returns (Key memory) {
        return getKey(keyHashes.at(i));
    }

    /// @inheritdoc IKeyManagement
    function getKey(bytes32 keyHash) public view returns (Key memory) {
        if (keyHash == KeyLib.ROOT_KEY_HASH) return KeyLib.toRootKey();
        if (keyHashes.contains(keyHash)) return abi.decode(keyStorage[keyHash], (Key));
        revert KeyDoesNotExist();
    }

    /// @inheritdoc IKeyManagement
    function getKeySettings(bytes32 keyHash) public view returns (Settings) {
        if (keyHash == KeyLib.ROOT_KEY_HASH) return SettingsLib.ROOT_KEY_SETTINGS;
        if (keyHashes.contains(keyHash)) return keySettings[keyHash];
        revert KeyDoesNotExist();
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Settings, SettingsLib} from "./libraries/SettingsLib.sol";
import {BaseAuthorization} from "./BaseAuthorization.sol";

/// @dev A base contract for managing keys
abstract contract KeyManagement is IKeyManagement, BaseAuthorization {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using KeyLib for bytes32;

    EnumerableSetLib.Bytes32Set keyHashes;
    mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
    mapping(bytes32 keyHash => Settings settings) keySettings;

    /// @inheritdoc IKeyManagement
    function register(Key memory key) external onlyThis {
        if (key.isRootKey()) revert CannotRegisterRootKey();

        bytes32 keyHash = key.hash();
        keyStorage[keyHash] = abi.encode(key);
        keyHashes.add(keyHash);

        emit Registered(keyHash, key);
    }

    function update(bytes32 keyHash, Settings settings) external onlyThis {
        if (keyHash.isRootKey()) revert CannotUpdateRootKey();
        if (!keyHashes.contains(keyHash)) revert KeyDoesNotExist();
        keySettings[keyHash] = settings;
    }

    /// @inheritdoc IKeyManagement
    function revoke(bytes32 keyHash) external onlyThis {
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
        if (keyHash.isRootKey()) return KeyLib.toRootKey();
        if (keyHashes.contains(keyHash)) return abi.decode(keyStorage[keyHash], (Key));
        revert KeyDoesNotExist();
    }

    /// @inheritdoc IKeyManagement
    function getKeySettings(bytes32 keyHash) public view returns (Settings) {
        if (keyHash.isRootKey()) return SettingsLib.ROOT_KEY_SETTINGS;
        if (keyHashes.contains(keyHash)) return keySettings[keyHash];
        revert KeyDoesNotExist();
    }
}

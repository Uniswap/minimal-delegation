// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {TestKey, TestKeyManager} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";

interface IHandlerGhostCallbacks {
    function ghost_RegisterCallback(Key memory key) external;
    function ghost_RevokeCallback(bytes32 keyHash) external;
    function ghost_UpdateCallback(bytes32 keyHash, Settings settings) external;
    function ghost_ExecuteCallback(Call[] memory calls) external;
}

/// Base contract for mirroring the state of signerAccount
abstract contract GhostStateTracker {
    using KeyLib for Key;
    using TestKeyManager for TestKey;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    EnumerableSetLib.Bytes32Set internal _ghostKeyHashes;
    mapping(bytes32 keyHash => bytes encodedKey) internal _ghostKeyStorage;
    mapping(bytes32 keyHash => Settings settings) internal _ghostKeySettings;

    /// @notice Ghost callback to track registered keys
    function ghost_RegisterCallback(Key memory key) external {
        bytes32 keyHash = key.hash();
        _ghostKeyHashes.add(keyHash);
        _ghostKeyStorage[keyHash] = abi.encode(key);
    }

    function ghost_RevokeCallback(bytes32 keyHash) external {
        _ghostKeyHashes.remove(keyHash);
        delete _ghostKeyStorage[keyHash];
        _ghostKeySettings[keyHash] = SettingsLib.DEFAULT;
    }

    // Noop
    function ghost_UpdateCallback(bytes32 keyHash, Settings settings) external {
        _ghostKeySettings[keyHash] = settings;
    }

    function ghost_ExecuteCallback(Call[] memory calls) external {}
}

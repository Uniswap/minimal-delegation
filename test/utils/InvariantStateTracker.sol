// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {TestKey, TestKeyManager} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";

interface IInvariantStateTracker {
    function registerCallback(Key memory key) external;
    function revokeCallback(bytes32 keyHash) external;
    function updateCallback(bytes32 keyHash, Settings settings) external;
    function executeCallback(Call[] memory calls) external;
}

/// Base contract for mirroring the state of signerAccount
/// Internal state must only be updated by callbacks, which are triggered sequentially in order of Call[] after each top level call to execute
abstract contract InvariantStateTracker {
    using KeyLib for Key;
    using TestKeyManager for TestKey;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    EnumerableSetLib.Bytes32Set internal _trackedKeyHashes;

    /// @notice Callback to track registered keys
    function registerCallback(Key memory key) external {
        bytes32 keyHash = key.hash();
        _trackedKeyHashes.add(keyHash);
    }

    function revokeCallback(bytes32 keyHash) external {
        _trackedKeyHashes.remove(keyHash);
    }

    // Noop
    function updateCallback(bytes32 keyHash, Settings settings) external {}

    function executeCallback(Call[] memory calls) external {}
}

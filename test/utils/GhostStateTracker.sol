// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {console2} from "forge-std/console2.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {TestKey, TestKeyManager} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";

interface IHandlerGhostCallbacks {
    function ghost_RegisterCallback(Key memory key) external;
    function ghost_RevokeCallback(bytes32 keyHash) external;
    function ghost_UpdateCallback(bytes32 keyHash) external;
    function ghost_ExecuteCallback(Call[] memory calls) external;
}

/// Base contract for mirroring the state of signerAccount
abstract contract GhostStateTracker {
    using KeyLib for Key;
    using TestKeyManager for TestKey;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    EnumerableSetLib.Bytes32Set internal _ghostKeyHashes;

    function _addKeyHash(bytes32 keyHash) internal {
        _ghostKeyHashes.add(keyHash);
    }

    /// @notice Ghost callback to track registered keys
    function ghost_RegisterCallback(Key memory key) external {
        _addKeyHash(key.hash());
    }

    function _removeKeyHash(bytes32 keyHash) internal {
        _ghostKeyHashes.remove(keyHash);
    }

    function ghost_RevokeCallback(bytes32 keyHash) external {
        _removeKeyHash(keyHash);
    }

    // Noop
    function ghost_UpdateCallback(bytes32 keyHash) external {}

    function ghost_ExecuteCallback(Call[] memory calls) external {}
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {console2} from "forge-std/console2.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {TestKey, TestKeyManager} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./SettingsBuilder.sol";

interface IInvariantCallbacks {
    function registerCallback(Key calldata) external;
    function revokeCallback(bytes32) external;
    function updateCallback(bytes32, Settings) external;
    function executeCallback(Call[] calldata) external;
}

struct InvariantState {
    uint256 registerSuccess;
    uint256 registerReverted;
    uint256 revokeSuccess;
    uint256 revokeReverted;
    uint256 updateSuccess;
    uint256 updateReverted;
    uint256 executeSuccess;
    uint256 executeReverted;
}

/// Base contract for mirroring the state of signerAccount
/// Internal state must only be updated by callbacks, which are triggered sequentially in order of Call[] after each top level call to execute
abstract contract InvariantFixtures {
    using SettingsBuilder for Settings;

    InvariantState internal _state;
    Settings[] internal fixtureSettings;

    // Warp to this time for keys with expiration to expire
    uint256 constant EXPIRATION_TIME = 100;

    constructor() {
        fixtureSettings.push(SettingsBuilder.init());
        fixtureSettings.push(SettingsBuilder.init().fromIsAdmin(true));
        fixtureSettings.push(SettingsBuilder.init().fromExpiration(uint40(EXPIRATION_TIME - 1)));
    }

    function _randSettings(uint256 randomSeed) internal view returns (Settings) {
        return fixtureSettings[randomSeed % fixtureSettings.length];
    }

    function logState() public view {
        console2.log("[register] success %s", _state.registerSuccess);
        console2.log("[register] reverted %s", _state.registerReverted);
        console2.log("[revoke] success %s", _state.revokeSuccess);
        console2.log("[revoke] reverted %s", _state.revokeReverted);
        console2.log("[update] success %s", _state.updateSuccess);
        console2.log("[update] reverted %s", _state.updateReverted);
        console2.log("[execute] success %s", _state.executeSuccess);
        console2.log("[execute] reverted %s", _state.executeReverted);
    }

    function registerCallback(Key memory key) external {
        _state.registerSuccess++;
    }

    function revokeCallback(bytes32 keyHash) external {
        _state.revokeSuccess++;
    }

    function updateCallback(bytes32 keyHash, Settings settings) external {
        _state.updateSuccess++;
    }

    function executeCallback(Call[] memory calls) external {
        _state.executeSuccess++;
    }
}

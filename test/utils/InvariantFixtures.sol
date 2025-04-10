// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {TestKey, TestKeyManager} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./SettingsBuilder.sol";
import {KeyType} from "../../src/libraries/KeyLib.sol";

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
    uint256 validationFailed_KeyExpired;
    uint256 validationFailed_KeyDoesNotExist;
    uint256 validationFailed_OnlyAdminCanSelfCall;
}

struct InvariantBlock {
    uint256 blockNumber;
    uint256 blockTimestamp;
}

/// Base contract for mirroring the state of signerAccount
/// Internal state must only be updated by callbacks, which are triggered sequentially in order of Call[] after each top level call to execute
abstract contract InvariantFixtures is Test {
    using SettingsBuilder for Settings;
    using TestKeyManager for TestKey;

    uint256 public constant MAX_KEYS = 10;

    // Keys that will be operated over in generated calldata
    TestKey[] internal fixtureKeys;
    Settings[] internal fixtureSettings;
    InvariantBlock[] internal fixtureBlocks;

    InvariantState internal _state;

    constructor() {
        // Generate MAX_KEYS and add to fixtureKey
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            fixtureKeys.push(TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint()));
        }

        uint256 expirationTime = block.timestamp + 100;
        fixtureSettings.push(SettingsBuilder.init());
        fixtureSettings.push(SettingsBuilder.init().fromIsAdmin(true));
        fixtureSettings.push(SettingsBuilder.init().fromExpiration(uint40(expirationTime)));

        // Add the current block
        fixtureBlocks.push(InvariantBlock({blockNumber: block.number, blockTimestamp: block.timestamp}));
        // Add a block which will be used for testing expiration
        fixtureBlocks.push(InvariantBlock({blockNumber: block.number + 1, blockTimestamp: expirationTime - 1}));
    }

    function _randKeyFromArray(TestKey[] storage _keys) internal returns (TestKey memory) {
        return _keys[vm.randomUint() % _keys.length];
    }

    function _randSettings() internal returns (Settings) {
        return fixtureSettings[vm.randomUint() % fixtureSettings.length];
    }

    function _randBlock() internal returns (InvariantBlock memory) {
        return fixtureBlocks[vm.randomUint() % fixtureBlocks.length];
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

        console2.log("[validationFailed] keyExpired %s", _state.validationFailed_KeyExpired);
        console2.log("[validationFailed] keyDoesNotExist %s", _state.validationFailed_KeyDoesNotExist);
        console2.log("[validationFailed] onlyAdminCanSelfCall %s", _state.validationFailed_OnlyAdminCanSelfCall);
    }

    function registerCallback(Key memory) external {
        _state.registerSuccess++;
    }

    function revokeCallback(bytes32) external {
        _state.revokeSuccess++;
    }

    function updateCallback(bytes32, Settings) external {
        _state.updateSuccess++;
    }

    function executeCallback(Call[] memory) external {
        _state.executeSuccess++;
    }
}

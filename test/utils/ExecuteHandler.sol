// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "../../src/interfaces/IMinimalDelegation.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Settings} from "../../src/libraries/SettingsLib.sol";
import {Key} from "../../src/libraries/KeyLib.sol";

/// @dev Helper contract for testing execute
contract ExecuteHandler {
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CAN_REVERT_CALL =
        0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA =
        0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;

    /// Helper functions for creating data for fuzz tests

    function _dataRegister(Key memory key) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IKeyManagement.register.selector, key);
    }

    function _dataRevoke(bytes32 keyHash) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IKeyManagement.revoke.selector, keyHash);
    }

    function _dataUpdate(bytes32 keyHash, Settings settings) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IKeyManagement.update.selector, keyHash, settings);
    }

    function _dataSelfBatchedCall(Call[] memory calls) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL, abi.encode(calls));
    }
}

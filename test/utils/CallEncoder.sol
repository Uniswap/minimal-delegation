// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallBuilder} from "./CallBuilder.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {Settings} from "../../src/libraries/SettingsLib.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";

/// @title CallEncoder
/// @dev Helper library to encode recursive self calls to execute
library CallEncoder {
    using CallBuilder for Call;
    using CallBuilder for Call[];
    using TestKeyManager for TestKey;

    address constant SELF_CALL = address(0);
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;

    function addExecute(Call[] memory calls, Call[] memory innerCalls) internal pure returns (Call[] memory) {
        return CallBuilder.push(calls, encodeExecuteCall(innerCalls));
    }

    function encodeExecuteCall(Call[] memory calls) internal pure returns (Call memory) {
        return CallBuilder.initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL, abi.encode(calls))
        );
    }

    function addRegister(Call[] memory calls, TestKey memory newKey) internal pure returns (Call[] memory) {
        return CallBuilder.push(calls, encodeRegisterCall(newKey));
    }

    function encodeRegisterCall(TestKey memory newKey) internal pure returns (Call memory) {
        return CallBuilder.initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.register.selector, newKey.toKey())
        );
    }

    function addRevoke(Call[] memory calls, bytes32 keyHash) internal pure returns (Call[] memory) {
        return CallBuilder.push(calls, encodeRevokeCall(keyHash));
    }

    function encodeRevokeCall(bytes32 keyHash) internal pure returns (Call memory) {
        return CallBuilder.initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.revoke.selector, keyHash)
        );
    }

    function addUpdate(Call[] memory calls, bytes32 keyHash, Settings settings) internal pure returns (Call[] memory) {
        return CallBuilder.push(calls, encodeUpdateCall(keyHash, settings));
    }

    function encodeUpdateCall(bytes32 keyHash, Settings settings) internal pure returns (Call memory) {
        return CallBuilder.initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.update.selector, keyHash, settings)
        );
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {Settings} from "../../src/libraries/SettingsLib.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";

/// @dev A wrapper around Call that includes callback data for processing after execution
struct HandlerCall {
    Call call; 
    bytes callback;
    bytes revertData;
}

/// @dev Utility library for Call and HandlerCall objects
library CallUtils {
    using CallUtils for Call;
    using CallUtils for Call[];
    using CallUtils for HandlerCall;
    using CallUtils for HandlerCall[];
    using TestKeyManager for TestKey;

    // Constants
    address constant SELF_CALL = address(0);
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;

    // Call array operations

    /// @dev Create empty Call array
    function initArray() internal pure returns (Call[] memory) {
        return new Call[](0);
    }

    /// @dev Add a call to an array
    function push(Call[] memory calls, Call memory call) internal pure returns (Call[] memory) {
        Call[] memory newCalls = new Call[](calls.length + 1);
        for (uint256 i = 0; i < calls.length; i++) {
            newCalls[i] = calls[i];
        }
        newCalls[calls.length] = call;
        return newCalls;
    }

    // Call manipulation

    /// @dev Create default empty Call
    function initDefault() internal pure returns (Call memory) {
        return Call({to: address(0), value: 0, data: ""});
    }

    function withTo(Call memory call, address to) internal pure returns (Call memory) {
        call.to = to;
        return call;
    }

    function withValue(Call memory call, uint256 value) internal pure returns (Call memory) {
        call.value = value;
        return call;
    }

    function withData(Call memory call, bytes memory data) internal pure returns (Call memory) {
        call.data = data;
        return call;
    }

    /// @dev Create call to execute a batch
    function encodeExecuteCall(Call[] memory calls) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL, abi.encode(calls))
        );
    }

    /// @dev Create call to register key
    function encodeRegisterCall(TestKey memory newKey) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.register.selector, newKey.toKey())
        );
    }

    /// @dev Create call to revoke key
    function encodeRevokeCall(bytes32 keyHash) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(abi.encodeWithSelector(IKeyManagement.revoke.selector, keyHash));
    }

    /// @dev Create call to update key settings
    function encodeUpdateCall(bytes32 keyHash, Settings settings) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.update.selector, keyHash, settings)
        );
    }

    // HandlerCall operations

    /// @dev Create empty HandlerCall array
    function initHandler() internal pure returns (HandlerCall[] memory) {
        return new HandlerCall[](0);
    }

    /// @dev Add a HandlerCall to array
    function push(HandlerCall[] memory handlerCalls, HandlerCall memory handlerCall)
        internal
        pure
        returns (HandlerCall[] memory)
    {
        HandlerCall[] memory newCalls = new HandlerCall[](handlerCalls.length + 1);
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            newCalls[i] = handlerCalls[i];
        }
        newCalls[handlerCalls.length] = handlerCall;
        return newCalls;
    }

    /// @dev Convert HandlerCall array to Call array
    function toCalls(HandlerCall[] memory handlerCalls) internal pure returns (Call[] memory) {
        Call[] memory calls = new Call[](handlerCalls.length);
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            calls[i] = handlerCalls[i].call;
        }
        return calls;
    }

    /// @dev Create default empty HandlerCall
    function initHandlerDefault() internal pure returns (HandlerCall memory) {
        return HandlerCall({call: Call({to: address(0), value: 0, data: ""}), callback: "", revertData: ""});
    }

    function withCall(HandlerCall memory handlerCall, Call memory call) internal pure returns (HandlerCall memory) {
        handlerCall.call = call;
        return handlerCall;
    }

    function withCallback(HandlerCall memory handlerCall, bytes memory callback)
        internal
        pure
        returns (HandlerCall memory)
    {
        handlerCall.callback = callback;
        return handlerCall;
    }

    function withRevertData(HandlerCall memory handlerCall, bytes memory revertData) internal pure returns (HandlerCall memory) {
        handlerCall.revertData = revertData;
        return handlerCall;
    }
}

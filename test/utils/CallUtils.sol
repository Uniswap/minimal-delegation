// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {Settings} from "../../src/libraries/SettingsLib.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";

/**
 * @title HandlerCall
 * @dev A wrapper around Call that includes callback data for processing after execution
 */
struct HandlerCall {
    Call call;
    bytes callback;
}

/**
 * @title CallUtils
 * @dev Consolidated utility library for creating, manipulating, and encoding Call objects for testing
 */
library CallUtils {
    using CallUtils for Call;
    using CallUtils for Call[];
    using CallUtils for HandlerCall;
    using CallUtils for HandlerCall[];
    using TestKeyManager for TestKey;

    // Constants
    address constant SELF_CALL = address(0);
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;

    //--------------------------------------------------------------------------------------//
    // Call array operations
    //--------------------------------------------------------------------------------------//

    /**
     * @notice Initialize an empty Call array
     */
    function init() internal pure returns (Call[] memory) {
        return new Call[](0);
    }

    /**
     * @notice Add a call to a call array
     * @param calls Existing call array
     * @param call Call to add
     * @return New call array with the added call
     */
    function push(Call[] memory calls, Call memory call) internal pure returns (Call[] memory) {
        Call[] memory newCalls = new Call[](calls.length + 1);
        for (uint256 i = 0; i < calls.length; i++) {
            newCalls[i] = calls[i];
        }
        newCalls[calls.length] = call;
        return newCalls;
    }

    //--------------------------------------------------------------------------------------//
    // Call manipulation
    //--------------------------------------------------------------------------------------//

    /**
     * @notice Initialize a default Call object
     */
    function initDefault() internal pure returns (Call memory) {
        return Call({to: address(0), value: 0, data: ""});
    }

    /**
     * @notice Set the 'to' field of a Call
     * @param call Call to modify
     * @param to Target address
     */
    function withTo(Call memory call, address to) internal pure returns (Call memory) {
        call.to = to;
        return call;
    }

    /**
     * @notice Set the 'value' field of a Call
     * @param call Call to modify
     * @param value ETH value to send
     */
    function withValue(Call memory call, uint256 value) internal pure returns (Call memory) {
        call.value = value;
        return call;
    }

    /**
     * @notice Set the 'data' field of a Call
     * @param call Call to modify
     * @param data Calldata to include
     */
    function withData(Call memory call, bytes memory data) internal pure returns (Call memory) {
        call.data = data;
        return call;
    }

    //--------------------------------------------------------------------------------------//
    // Call encoding for specific operations
    //--------------------------------------------------------------------------------------//

    /**
     * @notice Add an execute call to an existing call array
     * @param calls Existing call array
     * @param innerCalls Calls to execute
     */
    function addExecute(Call[] memory calls, Call[] memory innerCalls) internal pure returns (Call[] memory) {
        return push(calls, encodeExecuteCall(innerCalls));
    }

    /**
     * @notice Create a call that will execute a batch of calls
     * @param calls Calls to execute
     */
    function encodeExecuteCall(Call[] memory calls) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL, abi.encode(calls))
        );
    }

    /**
     * @notice Add a register key call to an existing call array
     * @param calls Existing call array
     * @param newKey Key to register
     */
    function addRegister(Call[] memory calls, TestKey memory newKey) internal pure returns (Call[] memory) {
        return push(calls, encodeRegisterCall(newKey));
    }

    /**
     * @notice Create a call that will register a key
     * @param newKey Key to register
     */
    function encodeRegisterCall(TestKey memory newKey) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.register.selector, newKey.toKey())
        );
    }

    /**
     * @notice Add a revoke key call to an existing call array
     * @param calls Existing call array
     * @param keyHash Hash of key to revoke
     */
    function addRevoke(Call[] memory calls, bytes32 keyHash) internal pure returns (Call[] memory) {
        return push(calls, encodeRevokeCall(keyHash));
    }

    /**
     * @notice Create a call that will revoke a key
     * @param keyHash Hash of key to revoke
     */
    function encodeRevokeCall(bytes32 keyHash) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.revoke.selector, keyHash)
        );
    }

    /**
     * @notice Add an update key settings call to an existing call array
     * @param calls Existing call array
     * @param keyHash Hash of key to update
     * @param settings New settings for the key
     */
    function addUpdate(Call[] memory calls, bytes32 keyHash, Settings settings) internal pure returns (Call[] memory) {
        return push(calls, encodeUpdateCall(keyHash, settings));
    }

    /**
     * @notice Create a call that will update key settings
     * @param keyHash Hash of key to update
     * @param settings New settings for the key
     */
    function encodeUpdateCall(bytes32 keyHash, Settings settings) internal pure returns (Call memory) {
        return initDefault().withTo(SELF_CALL).withData(
            abi.encodeWithSelector(IKeyManagement.update.selector, keyHash, settings)
        );
    }

    //--------------------------------------------------------------------------------------//
    // HandlerCall operations
    //--------------------------------------------------------------------------------------//

    /**
     * @notice Initialize an empty HandlerCall array
     */
    function initHandler() internal pure returns (HandlerCall[] memory) {
        return new HandlerCall[](0);
    }

    /**
     * @notice Add a HandlerCall to a HandlerCall array
     * @param handlerCalls Existing HandlerCall array
     * @param handlerCall HandlerCall to add
     */
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

    /**
     * @notice Convert a HandlerCall array to a Call array
     * @param handlerCalls HandlerCall array to convert
     */
    function toCalls(HandlerCall[] memory handlerCalls) internal pure returns (Call[] memory) {
        Call[] memory calls = new Call[](handlerCalls.length);
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            calls[i] = handlerCalls[i].call;
        }
        return calls;
    }

    /**
     * @notice Initialize a default HandlerCall
     */
    function initHandlerDefault() internal pure returns (HandlerCall memory) {
        return HandlerCall({call: Call({to: address(0), value: 0, data: ""}), callback: ""});
    }

    /**
     * @notice Set the 'call' field of a HandlerCall
     * @param handlerCall HandlerCall to modify
     * @param call Call to set
     */
    function withCall(HandlerCall memory handlerCall, Call memory call) internal pure returns (HandlerCall memory) {
        handlerCall.call = call;
        return handlerCall;
    }

    /**
     * @notice Set the 'callback' field of a HandlerCall
     * @param handlerCall HandlerCall to modify
     * @param callback Callback data to set
     */
    function withCallback(HandlerCall memory handlerCall, bytes memory callback)
        internal
        pure
        returns (HandlerCall memory)
    {
        handlerCall.callback = callback;
        return handlerCall;
    }
}
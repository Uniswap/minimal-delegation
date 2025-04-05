// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";

struct HandlerCall {
    Call call;
    bytes callback;
}

library HandlerCallLib {
    function init() internal pure returns (HandlerCall[] memory) {
        return new HandlerCall[](0);
    }

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

    function toCalls(HandlerCall[] memory handlerCalls) internal pure returns (Call[] memory) {
        Call[] memory calls = new Call[](handlerCalls.length);
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            calls[i] = handlerCalls[i].call;
        }
        return calls;
    }

    function initDefault() internal pure returns (HandlerCall memory) {
        return HandlerCall({call: Call({to: address(0), value: 0, data: ""}), callback: ""});
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
}
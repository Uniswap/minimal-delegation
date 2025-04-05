// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";

library CallBuilder {
    function init() internal pure returns (Call[] memory) {
        return new Call[](0);
    }

    function push(Call[] memory calls, Call memory call) internal pure returns (Call[] memory) {
        Call[] memory newCalls = new Call[](calls.length + 1);
        for (uint256 i = 0; i < calls.length; i++) {
            newCalls[i] = calls[i];
        }
        newCalls[calls.length] = call;
        return newCalls;
    }

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
}

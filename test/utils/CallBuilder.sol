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
}

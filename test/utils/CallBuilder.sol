// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Calls} from "../../src/interfaces/IERC7821.sol";

library CallBuilder {
    function init() internal pure returns (Calls[] memory) {
        return new Calls[](0);
    }

    function push(Calls[] memory calls, Calls memory call) internal pure returns (Calls[] memory) {
        Calls[] memory newCalls = new Calls[](calls.length + 1);
        for (uint256 i = 0; i < calls.length; i++) {
            newCalls[i] = calls[i];
        }
        newCalls[calls.length] = call;
        return newCalls;
    }
}

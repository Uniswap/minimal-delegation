// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {CalldataDecoder} from "../../src/libraries/CalldataDecoder.sol";
import {Call} from "../../src/libraries/CallLib.sol";

contract MockCalldataDecoder {
    using CalldataDecoder for bytes;

    function decodeCallsBytes(bytes calldata data) public pure returns (Call[] calldata calls, bytes calldata opData) {
        return data.decodeCallsBytes();
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {CalldataDecoder} from "../src/libraries/CalldataDecoder.sol";
import {MockCalldataDecoder} from "./utils/MockCalldataDecoder.sol";

contract CalldataDecoderTest is Test {
    using CalldataDecoder for bytes;

    MockCalldataDecoder decoder;

    function setUp() public {
        decoder = new MockCalldataDecoder();
    }

    function test_fuzz_decodeCallsBytes(Call[] calldata actualCalls, bytes calldata actualBytes) public view {
        (Call[] memory _calls, bytes memory _bytes) = decoder.decodeCallsBytes(abi.encode(actualCalls, actualBytes));

        for (uint256 i = 0; i < _calls.length; i++) {
            assertEq(_calls[i].to, actualCalls[i].to);
            assertEq(_calls[i].value, actualCalls[i].value);
            assertEq(_calls[i].data, actualCalls[i].data);
        }

        assertEq(_bytes, actualBytes);
    }
}

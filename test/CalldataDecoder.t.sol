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

    function test_removeSelector() public view {
        bytes4 selector = bytes4(keccak256("test"));
        bytes memory data = abi.encodeWithSelector(selector, uint256(1), uint256(2));
        bytes memory dataWithoutSelector = decoder.removeSelector(data);

        (uint256 one, uint256 two) = abi.decode(dataWithoutSelector, (uint256, uint256));
        assertEq(one, 1);
        assertEq(two, 2);
    }

    function test_decodeP256Signature_fuzz(bytes32 arg1, bytes32 arg2) public view {
        bytes memory data = abi.encode(arg1, arg2);
        (bytes32 _arg1, bytes32 _arg2) = decoder.decodeP256Signature(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
    }

    function test_decodeSignatureWithHookData_fuzz(bytes memory arg1, bytes memory arg2) public view {
        bytes memory data = abi.encode(arg1, arg2);
        (bytes memory _arg1, bytes memory _arg2) = decoder.decodeSignatureWithHookData(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
    }

    function test_decodeWrappedSignatureWithHookData_fuzz(bytes32 arg1, bytes memory arg2, bytes memory arg3)
        public
        view
    {
        bytes memory data = abi.encode(arg1, arg2, arg3);
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWrappedSignatureWithHookData(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
        assertEq(_arg3, arg3);
    }

    function test_decodeTypedDataSig_fuzz(bytes memory arg1, bytes32 arg2, bytes32 arg3, string memory arg4)
        public
        view
    {
        bytes memory data = abi.encode(arg1, arg2, arg3, arg4);
        (bytes memory _arg1, bytes32 _arg2, bytes32 _arg3, string memory _arg4) = decoder.decodeTypedDataSig(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
        assertEq(_arg3, arg3);
        assertEq(_arg4, arg4);
    }
}

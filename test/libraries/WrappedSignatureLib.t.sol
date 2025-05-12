// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {WrappedSignatureLib} from "../../src/libraries/WrappedSignatureLib.sol";
import {MockWrappedSignatureLib} from "../utils/MockWrappedSignatureLib.sol";

contract WrappedSignatureLibTest is Test {
    using WrappedSignatureLib for bytes;

    MockWrappedSignatureLib decoder;

    function setUp() public {
        decoder = new MockWrappedSignatureLib();
    }

    function test_decodeSignatureWithHookData_fuzz(bytes memory arg1, bytes memory arg2) public view {
        bytes memory data = abi.encode(arg1, arg2);
        (bytes memory _arg1, bytes memory _arg2) = decoder.decodeWithHookData(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
    }

    function test_decodeSignatureWithKeyHashAndHookData_fuzz(bytes32 arg1, bytes memory arg2, bytes memory arg3)
        public
        view
    {
        bytes memory data = abi.encode(arg1, arg2, arg3);
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
        assertEq(_arg3, arg3);
    }

    function test_decodeTypedDataSig_fuzz(bytes memory arg1, bytes32 arg2, bytes32 arg3, string memory arg4)
        public
        view
    {
        bytes memory data = abi.encode(arg1, arg2, arg3, arg4);
        (bytes memory _arg1, bytes32 _arg2, bytes32 _arg3, string memory _arg4) = decoder.decodeAsTypedDataSig(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
        assertEq(_arg3, arg3);
        assertEq(_arg4, arg4);
    }

    /// Offchain implementations may also encode the length of the contentsDescr in the calldata
    /// We do not use it in our implementation, but we should test that it does not affect the decoding of the other values
    function test_decodeTypedDataSig_withContentsDescrLength_fuzz(
        bytes memory arg1,
        bytes32 arg2,
        bytes32 arg3,
        string memory arg4,
        uint16 arg5
    ) public view {
        bytes memory data = abi.encode(arg1, arg2, arg3, arg4, arg5);
        (bytes memory _arg1, bytes32 _arg2, bytes32 _arg3, string memory _arg4) = decoder.decodeAsTypedDataSig(data);
        assertEq(_arg1, arg1);
        assertEq(_arg2, arg2);
        assertEq(_arg3, arg3);
        assertEq(_arg4, arg4);
    }

    function test_decodeSignatureWithHookData() public view {
        bytes memory data = abi.encode(bytes(""), bytes(""));
        (bytes memory _arg1, bytes memory _arg2) = decoder.decodeWithHookData(data);
        assertEq(_arg1, bytes(""));
        assertEq(_arg2, bytes(""));
    }

    function test_decodeSignatureWithHookData_incorrectlyEncodedSignature_reverts() public {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""));
        vm.expectRevert();
        decoder.decodeWithHookData(data);
    }

    function test_decodeSignatureWithHookData_incorrectlyEncodedHookData_reverts() public {
        bytes memory data = abi.encode(bytes(""));
        vm.expectRevert();
        decoder.decodeWithHookData(data);
    }

    function test_decodeSignatureWithHookData_incorrectlyEncodedHookData_inMemory_reverts() public {
        bytes memory data = abi.encode(bytes(""));
        vm.expectRevert();
        decoder.decodeSignatureWithHookDataInMemory(data);
    }

    function test_decodeWithKeyHashAndHookData() public view {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""), bytes(""));
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
        assertEq(_arg1, bytes32(keccak256("test")));
        assertEq(_arg2, bytes(""));
        assertEq(_arg3, bytes(""));
    }

    function test_decodeWithKeyHashAndHookData_incorrectlyEncodedSignature_reverts() public {
        bytes memory data = abi.encode(bytes32(keccak256("test")));
        vm.expectRevert();
        decoder.decodeWithKeyHashAndHookData(data);
    }

    function test_decodeWithKeyHashAndHookData_incorrectlyEncodedHookData_reverts() public {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""));
        vm.expectRevert();
        decoder.decodeWithKeyHashAndHookData(data);
    }

    function test_decodeWithKeyHashAndHookData_empty_succeeds() public view {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""), bytes(""));
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
        assertEq(_arg1, bytes32(keccak256("test")));
        assertEq(_arg2, bytes(""));
        assertEq(_arg3, bytes(""));
    }
}

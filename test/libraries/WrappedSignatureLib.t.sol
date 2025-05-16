// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {WrappedSignatureLib} from "../../src/libraries/WrappedSignatureLib.sol";
import {MockWrappedSignatureLib} from "../utils/MockWrappedSignatureLib.sol";

contract WrappedSignatureLibTest is Test {
    using WrappedSignatureLib for bytes;

    MockWrappedSignatureLib decoder;

    error InvalidSignatureLength();

    function setUp() public {
        decoder = new MockWrappedSignatureLib();
    }

    function test_decodeSignatureWithHookData_fuzz(bytes memory _signature, bytes memory _hookData) public {
        bytes memory data = abi.encode(_signature, _hookData);
        if (_signature.length == 0) {
            vm.expectRevert(abi.encodeWithSelector(InvalidSignatureLength.selector));
            decoder.decodeWithHookData(data);
        } else {
            (bytes memory _arg1, bytes memory _arg2) = decoder.decodeWithHookData(data);
            assertEq(_arg1, _signature);
            assertEq(_arg2, _hookData);
        }
    }

    function test_decodeSignatureWithKeyHashAndHookData_fuzz(
        bytes32 _keyHash,
        bytes memory _signature,
        bytes memory _hookData
    ) public {
        bytes memory data = abi.encode(_keyHash, _signature, _hookData);
        if (_signature.length == 0) {
            vm.expectRevert(abi.encodeWithSelector(InvalidSignatureLength.selector));
            decoder.decodeWithKeyHashAndHookData(data);
        } else {
            (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
            assertEq(_arg1, _keyHash);
            assertEq(_arg2, _signature);
            assertEq(_arg3, _hookData);
        }
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
        bytes memory data = abi.encode(bytes("test"), bytes(""));
        (bytes memory _arg1, bytes memory _arg2) = decoder.decodeWithHookData(data);
        assertEq(_arg1, bytes("test"));
        assertEq(_arg2, bytes(""));
    }

    function test_decodeSignatureWithHookData_incorrectlyEncodedSignature_reverts() public {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""));
        vm.expectRevert();
        decoder.decodeWithHookData(data);
    }

    function test_decodeWithKeyHashAndHookData() public view {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes("test"), bytes(""));
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
        assertEq(_arg1, bytes32(keccak256("test")));
        assertEq(_arg2, bytes("test"));
        assertEq(_arg3, bytes(""));
    }

    // In memory version
    // reverts
    function test_decodeWithKeyHashAndHookData_incorrectlyEncodedKeyHash_inMemory_reverts() public {
        bytes memory data = abi.encode(bytes("4444"));
        vm.expectRevert();
        decoder.decodeWithKeyHashAndHookDataInMemory(data);
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

    function test_decodeWithKeyHashAndHookData_empty_reverts_withInvalidSignatureLength() public {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""), bytes(""));
        vm.expectRevert(abi.encodeWithSelector(InvalidSignatureLength.selector));
        decoder.decodeWithKeyHashAndHookData(data);
    }
}

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

    // Calldata version
    // Doesnt revert but returns bad values
    function test_decodeWithKeyHashAndHookData_incorrectlyEncodedKeyHash_reverts() public {
        bytes memory data = abi.encode(bytes("4444"));
        /**
        ├ Hex (Tuple Encoded):
        ├─ Pointer ([0x00:0x20]):  0x0000000000000000000000000000000000000000000000000000000000000020 // offset for abi.encode(bytes("4444"))
        ├─ Length ([0x20:0x40]):   0x0000000000000000000000000000000000000000000000000000000000000060 // length of abi.encode(bytes("4444"))
        └─ Contents ([0x40:0x60]): 0x0000000000000000000000000000000000000000000000000000000000000020 // offset for bytes("4444")
                     [0x60:0x80]:  0x0000000000000000000000000000000000000000000000000000000000000004 // length of bytes("4444")
                     [0x80:0xA0]:  0x3434343400000000000000000000000000000000000000000000000000000000 // bytes("4444")
         */

        // data.offset = 0x44
        // keyHash := calldataload(data.offset)                                         // 0x40:0x60 (0x0000000000000000000000000000000000000000000000000000000000000020)
        // toSafeBytes(1)
        // -> lengthPtr := add(0x44, and(calldataload(add(0x44, 0x20)), 0xffffffff)))
        // ->              add(0x44, and(calldataload(0x64), 0xffffffff))
        // ->              add(0x44, and(0x04, 0xffffffff))
        // ->              add(0x44, 0x04) = 0x48 (verified by log output)
        // -> length := and(calldataload(lengthPtr), OFFSET_OR_LENGTH_MASK)
        // ->              and(calldataload(0x48), 0xffffffff)                         // 0x48:0x68 (0x00000000000000000000000000000000000000000000200000000000000000000)
        // ->              and(9x200000000000000000000 , 0xffffffff) = 0x00
        // -> offset := add(lengthPtr, 0x20)
        // ->              add(0x48, 0x20) = 0x68 (verified by log output)
        // -> res.length := length
        // ->              length = 0x00 (output from above)
        // -> res.offset := offset
        // ->              offset = 0x68
        // -> if lt(add(_bytes.length, _bytes.offset), add(length, offset)) {
        // ->              lt(add(0x60, 0x44), add(0x00, 0x68))
        // ->              lt(0xa4, 0x68)
        // ->              false
        // -> No revert
        vm.expectRevert();
        decoder.decodeWithKeyHashAndHookData(data);
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

    function test_decodeWithKeyHashAndHookData_empty_succeeds() public view {
        bytes memory data = abi.encode(bytes32(keccak256("test")), bytes(""), bytes(""));
        (bytes32 _arg1, bytes memory _arg2, bytes memory _arg3) = decoder.decodeWithKeyHashAndHookData(data);
        assertEq(_arg1, bytes32(keccak256("test")));
        assertEq(_arg2, bytes(""));
        assertEq(_arg3, bytes(""));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CalldataLib} from "../../src/libraries/CalldataLib.sol";
import {Call} from "../../src/libraries/CallLib.sol";

contract CalldataLibTest is Test {
    // External function to test the library with calldata
    function parseExecutionDataExternal(bytes calldata executionData)
        external
        pure
        returns (Call[] memory calls, bytes memory opData)
    {
        return CalldataLib.parseExecutionData(executionData);
    }

    function test_parseExecutionData_succeeds() public {
        // Create valid test data
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(0x1), value: 1 ether, data: hex"deadbeef"});
        calls[1] = Call({to: address(0x2), value: 0.5 ether, data: hex"beefdead"});

        bytes memory opData = hex"1234567890";

        bytes memory executionData = abi.encode(calls, opData);

        // Parse the data using CalldataLib
        (Call[] memory parsedCalls, bytes memory parsedOpData) = this.parseExecutionDataExternal(executionData);

        // Verify the results
        assertEq(parsedCalls.length, calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            assertEq(parsedCalls[i].to, calls[i].to);
            assertEq(parsedCalls[i].value, calls[i].value);
            assertEq(parsedCalls[i].data, calls[i].data);
        }
        assertEq(parsedOpData, opData);
    }

    function test_parseExecutionData_reverts_correctly() public {
        // Offset points beyond calldata length
        bytes memory maliciousData1 = _generateCalldata(type(uint256).max, 0);
        vm.expectRevert();
        this.parseExecutionDataExternal(maliciousData1);

        // Valid offset but invalid length
        bytes memory maliciousData2 = _generateCalldata(0x40, type(uint256).max);
        vm.expectRevert();
        this.parseExecutionDataExternal(maliciousData2);

        // OpData offset points to invalid location
        bytes memory maliciousData3 = _generateCalldata(0x40, 1, type(uint256).max);
        vm.expectRevert();
        this.parseExecutionDataExternal(maliciousData3);
    }

    function test_parseExecutionData_reverts_on_empty_data() public {
        bytes memory emptyData = new bytes(0);
        vm.expectRevert();
        this.parseExecutionDataExternal(emptyData);
    }

    function test_parseExecutionData_reverts_on_malformed_array_length() public {
        // Create a calls array with malformed length
        Call[] memory calls = new Call[](1);
        calls[0] = Call({to: address(0x1), value: 1 ether, data: hex"dead"});

        bytes memory executionData = abi.encode(calls);
        // Corrupt the array length
        assembly {
            mstore(add(executionData, 0x40), 0xffffffff)
        }

        vm.expectRevert();
        this.parseExecutionDataExternal(executionData);
    }

    function test_parseExecutionData_reverts_on_invalid_opData_offset() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({to: address(0x1), value: 1 ether, data: hex"dead"});
        bytes memory opData = hex"1234";

        bytes memory executionData = abi.encode(calls, opData);
        // Corrupt the opData offset to point to an invalid location
        assembly {
            mstore(add(executionData, 0x20), add(mload(executionData), 0x20))
        }

        vm.expectRevert();
        this.parseExecutionDataExternal(executionData);
    }

    function _generateCalldata(uint256 offset, uint256 length) internal pure returns (bytes memory) {
        return abi.encodePacked(
            offset, // offset to calls array
            length // length of calls array
        );
    }

    function _generateCalldata(uint256 callsOffset, uint256 callsLength, uint256 opDataOffset)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            callsOffset, // offset to calls array
            opDataOffset, // offset to opData
            callsLength // length of calls array
        );
    }
}

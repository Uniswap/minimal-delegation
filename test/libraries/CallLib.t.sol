// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Call, CallLib} from "../../src/libraries/CallLib.sol";

contract CallLibTest is Test {
    using CallLib for Call[];

    /// @notice Test to catch accidental changes to the typehash
    function test_constant_call_typehash() public pure {
        bytes32 expectedTypeHash = keccak256("Call(address to,uint256 value,bytes data)");
        assertEq(CallLib.CALL_TYPEHASH, expectedTypeHash);
    }

    function test_hash_single_fuzz(address to, uint256 value, bytes calldata data) public pure {
        Call memory call = Call({to: to, value: value, data: data});
        bytes32 actualHash = CallLib.hash(call);

        bytes32 expectedHash = keccak256(abi.encode(CallLib.CALL_TYPEHASH, call.to, call.value, keccak256(call.data)));
        assertEq(actualHash, expectedHash);
    }

    function test_hash_multiple_fuzz(Call[] memory calls) public pure {
        bytes32 actualHash = CallLib.hash(calls);

        bytes32[] memory hashes = new bytes32[](calls.length);

        // Pack hashes into bytes array
        for (uint256 i = 0; i < calls.length; i++) {
            hashes[i] = CallLib.hash(calls[i]);
        }

        bytes32 expectedHash = keccak256(abi.encodePacked(hashes));

        assertEq(actualHash, expectedHash);
    }
}

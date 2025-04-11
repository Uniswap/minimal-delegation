// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Call, CallLib} from "../../src/libraries/CallLib.sol";
import {CallUtils} from "../utils/CallUtils.sol";
import {SignedBatchedCalls, SignedBatchedCallsLib} from "../../src/libraries/SignedBatchedCallsLib.sol";
import {BatchedCalls, BatchedCallsLib} from "../../src/libraries/BatchedCallsLib.sol";

contract SignedCallsLibTest is Test {
    using CallLib for Call[];
    using CallUtils for *;
    using BatchedCallsLib for BatchedCalls;
    using SignedBatchedCallsLib for SignedBatchedCalls;

    /// @notice Test to catch accidental changes to the typehash
    function test_constant_execution_data_typehash() public pure {
        bytes32 expectedTypeHash = keccak256(
            "SignedBatchedCalls(BatchedCalls batchedCalls,uint256 nonce,bytes32 keyHash,bool shouldRevert)BatchedCalls(Call[] calls,bool shouldRevert)Call(address to,uint256 value,bytes data)"
        );
        assertEq(SignedBatchedCallsLib.SIGNED_BATCHED_CALLS_TYPEHASH, expectedTypeHash);
    }

    function test_hash_with_nonce_fuzz(Call[] memory calls, uint256 nonce, bytes32 keyHash, bool shouldRevert)
        public
        pure
    {
        BatchedCalls memory batchedCalls = CallUtils.initBatchedCalls().withCalls(calls).withShouldRevert(shouldRevert);
        SignedBatchedCalls memory signedBatchedCalls =
            CallUtils.initSignedBatchedCalls().withBatchedCalls(batchedCalls).withNonce(nonce).withKeyHash(keyHash);
        bytes32 actualHash = signedBatchedCalls.hash();

        bytes32 expectedHash = keccak256(
            abi.encode(SignedBatchedCallsLib.SIGNED_BATCHED_CALLS_TYPEHASH, batchedCalls.hash(), nonce, keyHash)
        );
        assertEq(actualHash, expectedHash);
    }
}

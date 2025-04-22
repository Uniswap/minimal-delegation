// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Call, CallLib} from "../../src/libraries/CallLib.sol";
import {CallUtils} from "../utils/CallUtils.sol";
import {SignedBatchedCall, SignedBatchedCallLib} from "../../src/libraries/SignedBatchedCallLib.sol";
import {BatchedCall, BatchedCallLib} from "../../src/libraries/BatchedCallLib.sol";

contract SignedBatchedCallLibTest is Test {
    using CallLib for Call[];
    using CallUtils for *;
    using BatchedCallLib for BatchedCall;
    using SignedBatchedCallLib for SignedBatchedCall;

    /// @notice Test to catch accidental changes to the typehash
    function test_constant_execution_data_typehash() public pure {
        bytes32 expectedTypeHash = keccak256(
            "SignedBatchedCall(BatchedCall batchedCall,uint256 nonce,bytes32 keyHash,address executor)BatchedCall(Call[] calls,bool revertOnFailure)Call(address to,uint256 value,bytes data)"
        );
        assertEq(SignedBatchedCallLib.SIGNED_BATCHED_CALL_TYPEHASH, expectedTypeHash);
    }

    function test_hash_with_nonce_fuzz(Call[] memory calls, uint256 nonce, bytes32 keyHash, bool revertOnFailure)
        public
        pure
    {
        BatchedCall memory batchedCall = CallUtils.initBatchedCall().withCalls(calls).withShouldRevert(revertOnFailure);
        SignedBatchedCall memory signedBatchedCall =
            CallUtils.initSignedBatchedCall().withBatchedCall(batchedCall).withNonce(nonce).withKeyHash(keyHash);
        bytes32 actualHash = signedBatchedCall.hash();

        bytes32 expectedHash = keccak256(
            abi.encode(
                SignedBatchedCallLib.SIGNED_BATCHED_CALL_TYPEHASH, batchedCall.hash(), nonce, keyHash, address(0)
            )
        );
        assertEq(actualHash, expectedHash);
    }
}

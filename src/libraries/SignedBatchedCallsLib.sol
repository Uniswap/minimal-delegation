// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BatchedCallsLib, BatchedCalls} from "./BatchedCallsLib.sol";

struct SignedBatchedCalls {
    BatchedCalls batchedCalls;
    uint256 nonce;
    bytes32 keyHash;
}

/// @title SignedBatchedCallsLib
/// @notice Library for EIP-712 hashing of SignedBatchedCalls
library SignedBatchedCallsLib {
    using BatchedCallsLib for BatchedCalls;

    /// @dev The type string for the SignedCalls struct
    bytes internal constant SIGNED_BATCHED_CALLS_TYPE =
        "SignedBatchedCalls(BatchedCalls batchedCalls,uint256 nonce,bytes32 keyHash)BatchedCalls(Call[] calls,bool shouldRevert)Call(address to,uint256 value,bytes data)";
    /// @dev The typehash for the SignedCalls struct
    bytes32 internal constant SIGNED_BATCHED_CALLS_TYPEHASH = keccak256(SIGNED_BATCHED_CALLS_TYPE);

    /// @notice Hashes a SignedBatchedCalls struct.
    function hash(SignedBatchedCalls memory signedBatchedCalls) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNED_BATCHED_CALLS_TYPEHASH,
                signedBatchedCalls.batchedCalls.hash(),
                signedBatchedCalls.nonce,
                signedBatchedCalls.keyHash
            )
        );
    }
}

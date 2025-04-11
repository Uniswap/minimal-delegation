// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Call, CallLib} from "./CallLib.sol";

struct BatchedCalls {
    Call[] calls;
    bool shouldRevert;
}

/// @title BatchedCallsLib
/// @notice Library for EIP-712 hashing of BatchedCalls
library BatchedCallsLib {
    using CallLib for Call[];

    /// @dev The type string for the BatchedCall struct
    bytes internal constant BATCHED_CALLS_TYPE =
        "BatchedCalls(Call[] calls,bool shouldRevert)Call(address to,uint256 value,bytes data)";
    /// @dev The typehash for the BatchedCall struct
    bytes32 internal constant BATCHED_CALLS_TYPEHASH = keccak256(BATCHED_CALLS_TYPE);

    function hash(BatchedCalls memory batchedCalls) internal pure returns (bytes32) {
        return keccak256(abi.encode(BATCHED_CALLS_TYPEHASH, batchedCalls.calls.hash(), batchedCalls.shouldRevert));
    }
}

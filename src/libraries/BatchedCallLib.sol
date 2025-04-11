// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Call, CallLib} from "./CallLib.sol";

struct BatchedCall {
    Call[] calls;
    bool shouldRevert;
}

/// @title BatchedCallLib
/// @notice Library for EIP-712 hashing of BatchedCall
library BatchedCallLib {
    using CallLib for Call[];

    /// @dev The type string for the BatchedCall struct
    bytes internal constant BATCHED_CALLS_TYPE =
        "BatchedCall(Call[] calls,bool shouldRevert)Call(address to,uint256 value,bytes data)";
    /// @dev The typehash for the BatchedCall struct
    bytes32 internal constant BATCHED_CALLS_TYPEHASH = keccak256(BATCHED_CALLS_TYPE);

    function hash(BatchedCall memory batchedCall) internal pure returns (bytes32) {
        return keccak256(abi.encode(BATCHED_CALLS_TYPEHASH, batchedCall.calls.hash(), batchedCall.shouldRevert));
    }
}

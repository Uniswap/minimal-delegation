// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @dev Helper contract for testing execute
contract ExecuteHandler {
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CAN_REVERT_CALL =
        0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA =
        0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_USER_OP = 0x0100000000007821433700000000000000000000000000000000000000000000;
}

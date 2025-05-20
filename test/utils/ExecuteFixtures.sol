// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @dev Helper contract for testing execute
abstract contract ExecuteFixtures {
    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CAN_REVERT_CALL =
        0x0101000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant DEFAULT_NONCE = 0;
}

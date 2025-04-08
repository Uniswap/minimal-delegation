// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice This is a temporary library that allows us to use transient storage (tstore/tload)
/// TODO: This library can be deleted when we have the transient keyword support in solidity.
library TransientAllowance {
    /// @notice calculates which storage slot a transient allowance should be stored in for a given spender
    function _computeSlot(address spender) internal pure returns (bytes32 hashSlot) {
        assembly ("memory-safe") {
            mstore(0, and(spender, 0xffffffffffffffffffffffffffffffffffffffff))
            hashSlot := keccak256(0, 32)
        }
    }

    function get(address spender) internal view returns (uint256 allowance) {
        bytes32 hashSlot = _computeSlot(spender);
        assembly ("memory-safe") {
            allowance := tload(hashSlot)
        }
    }

    function set(address spender, uint256 allowance) internal {
        bytes32 hashSlot = _computeSlot(spender);
        assembly ("memory-safe") {
            tstore(hashSlot, allowance)
        }
    }
}

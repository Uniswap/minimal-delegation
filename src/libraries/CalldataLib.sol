// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Call} from "./CallLib.sol";

/// @author Modified from https://github.com/Vectorized/solady/blob/main/src/accounts/LibERC7579.sol
library CalldataLib {
    /// @dev Returns whether the `executionData` has optional `opData`.
    function hasOpData(bytes calldata executionData) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            // Checks if length >= 64 (0x40) AND first offset >= 64 (0x40)
            result := iszero(or(lt(executionData.length, 0x40), lt(calldataload(executionData.offset), 0x40)))
        }
    }

    /// @notice Parse the execution data and return the calls and opData, if present
    /// @dev If opData is present it expects the executionData to have been encoded as (Call[], bytes)
    function parseExecutionData(bytes calldata executionData)
        internal
        pure
        returns (Call[] calldata calls, bytes calldata opData)
    {
        bool _hasOpData = hasOpData(executionData);
        // @solidity memory-safe-assembly
        assembly {
            // Set opData to empty
            opData.length := 0
            opData.offset := 0

            // Load calls
            let o := add(executionData.offset, calldataload(executionData.offset))
            calls.offset := add(o, 0x20)
            calls.length := calldataload(o)

            // Validate calls length, revert if out of bounds
            if gt(add(calls.offset, calls.length), add(executionData.offset, executionData.length)) { revert(0, 0) }

            if _hasOpData {
                // Load opData offset and validate its length
                let opDataOffset := calldataload(add(executionData.offset, 0x20))
                if gt(opDataOffset, sub(executionData.length, 32)) { revert(0, 0) }

                let q := add(executionData.offset, opDataOffset)
                opData.offset := add(q, 0x20)
                opData.length := calldataload(q)

                // Validate opData length
                if gt(add(opData.offset, opData.length), add(executionData.offset, executionData.length)) {
                    revert(0, 0)
                }
            }
        }
    }
}

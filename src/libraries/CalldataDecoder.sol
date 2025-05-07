// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title CalldataDecoder
library CalldataDecoder {
    /// error SliceOutOfBounds();
    uint256 constant SLICE_ERROR_SELECTOR = 0x3b99b53d;

    /// @notice Removes the selector from the calldata and returns the encoded params.
    function removeSelector(bytes calldata data) internal pure returns (bytes calldata params) {
        assembly {
            if lt(data.length, 4) {
                mstore(0, SLICE_ERROR_SELECTOR)
                revert(0x1c, 4)
            }
            params.offset := add(data.offset, 4)
            params.length := sub(data.length, 4)
        }
    }
}

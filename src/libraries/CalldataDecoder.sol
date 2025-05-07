// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/console2.sol";

/// @title CalldataDecoder
library CalldataDecoder {
    /// @notice Removes the selector from the calldata and returns the encoded params.
    function removeSelector(bytes calldata data) internal pure returns (bytes calldata params) {
        uint256 length;
        assembly {
            length := data.length
            params.offset := add(data.offset, 4)
            params.length := sub(data.length, 4)
        }

        console2.log("length", length);
    }
}

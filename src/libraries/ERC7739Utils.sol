// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {LibString} from "solady/utils/LibString.sol";

/// @title ERC7739Utils
/// @notice Modified from the original implementation at
/// https://github.com/OpenZeppelin/openzeppelin-community-contracts/blob/53f590e4f4902bee0e06e455332e3321c697ea8b/contracts/utils/cryptography/ERC7739Utils.sol
/// Changelog
/// - Use in memory strings
/// - Use Solady's LibString for memory string operations
library ERC7739Utils {
    /**
     * @dev Parse the type name out of the ERC-7739 contents type description. Supports both the implicit and explicit
     * modes.
     *
     * Following ERC-7739 specifications, a `contentsName` is considered invalid if it's empty or it contains
     * any of the following bytes , )\x00
     *
     * If the `contentsType` is invalid, this returns an empty string. Otherwise, the return string has non-zero
     * length.
     */
    function decodeContentsDescr(string memory contentsDescr)
        internal
        pure
        returns (string memory contentsName, string memory contentsType)
    {
        bytes memory buffer = bytes(contentsDescr);
        if (buffer.length == 0) {
            // pass through (fail)
        } else if (buffer[buffer.length - 1] == bytes1(")")) {
            // Implicit mode: read contentsName from the beginning, and keep the complete descr
            for (uint256 i = 0; i < buffer.length; ++i) {
                bytes1 current = buffer[i];
                if (current == bytes1("(")) {
                    // if name is empty - passthrough (fail)
                    if (i == 0) break;
                    // we found the end of the contentsName
                    contentsName = LibString.slice(contentsDescr, 0, i);
                    contentsType = contentsDescr;
                    return (contentsName, contentsType);
                } else if (_isForbiddenChar(current)) {
                    // we found an invalid character (forbidden) - passthrough (fail)
                    break;
                }
            }
        } else {
            // Explicit mode: read contentsName from the end, and remove it from the descr
            for (uint256 i = buffer.length; i > 0; --i) {
                bytes1 current = buffer[i - 1];
                if (current == bytes1(")")) {
                    // we found the end of the contentsName
                    contentsName = LibString.slice(contentsDescr, i, buffer.length);
                    contentsType = LibString.slice(contentsDescr, 0, i);
                    return (contentsName, contentsType);
                } else if (_isForbiddenChar(current)) {
                    // we found an invalid character (forbidden) - passthrough (fail)
                    break;
                }
            }
        }
        return ("", "");
    }

    /// @dev Perform some onchain sanitization of contentsName as defined by the ERC-7739 spec
    function _isForbiddenChar(bytes1 char) private pure returns (bool) {
        return char == 0x00 || char == bytes1(" ") || char == bytes1(",") || char == bytes1("(") || char == bytes1(")");
    }
}

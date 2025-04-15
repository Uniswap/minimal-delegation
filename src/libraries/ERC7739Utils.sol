// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {LibString} from "solady/utils/LibString.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PersonalSignLib} from "./PersonalSignLib.sol";
import {TypedDataSignLib} from "./TypedDataSignLib.sol";

/// @title ERC7739Utils
/// @notice Modified from the original implementation at
/// https://github.com/OpenZeppelin/openzeppelin-community-contracts/blob/53f590e4f4902bee0e06e455332e3321c697ea8b/contracts/utils/cryptography/ERC7739Utils.sol
/// Changelog
/// - Use in memory strings
/// - Use Solady's LibString for memory string operations
library ERC7739Utils {
    /// @notice Hash a PersonalSign struct with the app's domain separator to produce an EIP-712 compatible hash
    /// @dev Uses this account's domain separator in the EIP-712 hash for replay protection
    /// @param hash The hashed message, calculated offchain
    /// @param domainSeparator This account's domain separator
    /// @return The PersonalSign nested EIP-712 hash of the message
    function toPersonalSignTypedDataHash(bytes32 hash, bytes32 domainSeparator) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator, PersonalSignLib.hash(hash));
    }

    /// @notice Hash TypedDataSign with the app's domain separator to produce an EIP-712 compatible hash
    /// @dev Includes this account's domain in the hash for replay protection
    /// @param contentsHash The hash of the contents, per EIP-712
    /// @param domainBytes The encoded domain bytes from EIP-5267
    /// @param appSeparator The app's domain separator
    /// @param contentsName The top level type, per EIP-712
    /// @param contentsType The full type string of the contents, per EIP-712
    function toNestedTypedDataSignHash(
        bytes32 contentsHash,
        bytes memory domainBytes,
        bytes32 appSeparator,
        string memory contentsName,
        string memory contentsType
    ) internal view returns (bytes32) {
        bytes32 typedDataSignHash = TypedDataSignLib.hash(contentsName, contentsType, contentsHash, domainBytes);
        return MessageHashUtils.toTypedDataHash(appSeparator, typedDataSignHash);
    }

    /// @notice Parse the type name out of the ERC-7739 contents type description. Supports both the implicit and explicit modes
    /// @dev Returns empty strings if the contentsDescr is invalid, which must be handled by the calling function
    /// @return contentsName The type name of the contents
    /// @return contentsType The type description of the contents
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

    /// @notice Perform onchain sanitization of contentsName as defined by the ERC-7739 spec
    /// @dev Following ERC-7739 specifications, a `contentsName` is considered invalid if it's empty or it contains
    /// any of the following bytes: ", )\x00"
    function _isForbiddenChar(bytes1 char) private pure returns (bool) {
        return char == 0x00 || char == bytes1(" ") || char == bytes1(",") || char == bytes1("(") || char == bytes1(")");
    }
}

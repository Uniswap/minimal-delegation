// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {LibString} from "solady/utils/LibString.sol";

/**
 * @dev Utilities to process https://ercs.ethereum.org/ERCS/erc-7739[ERC-7739] typed data signatures
 * that are specific to an EIP-712 domain.
 *
 * This library provides methods to wrap, unwrap and operate over typed data signatures with a defensive
 * rehashing mechanism that includes the application's
 * https://docs.openzeppelin.com/contracts/api/utils#EIP712-_domainSeparatorV4[EIP-712]
 * and preserves readability of the signed content using an EIP-712 nested approach.
 *
 * A smart contract domain can validate a signature for a typed data structure in two ways:
 *
 * - As an application validating a typed data signature. See {typedDataSignStructHash}.
 * - As a smart contract validating a raw message signature. See {personalSignStructHash}.
 *
 * NOTE: A provider for a smart contract wallet would need to return this signature as the
 * result of a call to `personal_sign` or `eth_signTypedData`, and this may be unsupported by
 * API clients that expect a return value of 129 bytes, or specifically the `r,s,v` parameters
 * of an https://docs.openzeppelin.com/contracts/api/utils#ECDSA[ECDSA] signature, as is for
 * example specified for https://docs.openzeppelin.com/contracts/api/utils#EIP712[EIP-712].
 */

// Modified from source
library ERC7739Utils {
    /**
     * @notice Modified from the original implementation:
     * - Use in memory strings
     * - Use LibString.slice
     *
     * @dev Parse the type name out of the ERC-7739 contents type description. Supports both the implicit and explicit
     * modes.
     *
     * Following ERC-7739 specifications, a `contentsName` is considered invalid if it's empty or it contains
     * any of the following bytes , )\x00
     *
     * If the `contentsType` is invalid, this returns an empty string. Otherwise, the return string has non-zero
     * length.
     */
    function decodeContentsDescription(string memory contentsDescription)
        internal
        pure
        returns (string memory contentsName, string memory contentsType)
    {
        bytes memory buffer = bytes(contentsDescription);
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
                    contentsName = LibString.slice(contentsDescription, 0, i);
                    contentsType = contentsDescription;
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
                    contentsName = LibString.slice(contentsDescription, i, buffer.length);
                    contentsType = LibString.slice(contentsDescription, 0, i);
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

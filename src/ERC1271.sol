// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC1271} from "./interfaces/IERC1271.sol";
import {EIP712} from "./EIP712.sol";

/// @title ERC-1271
///
/// @notice Abstract ERC1271 implementation protecting against cross account replay attacks.
///
/// @author Uniswap
/// @author Modified from Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Modified from Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
abstract contract ERC1271 is IERC1271, EIP712 {
    /// @dev The magic value returned by `isValidSignature()` if the signature is valid.
    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    /// @dev The magic value returned by `isValidSignature()` if the signature is invalid.
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

    /// @notice Validates the `signature` against the given `hash`.
    /// @dev Hashes the given `hash` to be replay safe and validates the signature against it.
    ///
    /// @return result `0x1626ba7e` if validation succeeded, else `0xffffffff`.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (_isValidSignature({hash: _hashTypedData(hash), signature: signature})) {
            return _1271_MAGIC_VALUE;
        }

        return _1271_INVALID_VALUE;
    }

    /// @notice Validates the `signature` against the given `hash`.
    /// @return `true` is the signature is valid, else `false`.
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual returns (bool);
}

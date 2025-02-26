// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EIP712} from "./EIP712.sol";

/// @title ERC-1271
///
/// @notice Abstract ERC1271 implementation protecting against cross account replay attacks.
///
/// @author Uniswap
/// @author Modified from Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Modified from Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
abstract contract ERC1271 is EIP712 {
    /// @notice Validates the `signature` against the given `hash`.
    ///
    /// @dev This implementation follows ERC-1271. See https://eips.ethereum.org/EIPS/eip-1271.
    /// @dev IMPORTANT: Signature verification is performed on the hash produced AFTER applying the anti
    ///      cross-account-replay layer on the given `hash` (i.e., verification is run on the replay-safe
    ///      hash version).
    ///
    /// @param hash      The original hash.
    /// @param signature The signature of the replay-safe hash to validate.
    ///
    /// @return result `0x1626ba7e` if validation succeeded, else `0xffffffff`.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (_isValidSignature({hash: replaySafeHash(hash), signature: signature})) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /// @notice Wrapper around `_eip712Hash()` to produce a replay-safe hash fron the given `hash`.
    ///
    /// @dev The returned EIP-712 compliant replay-safe hash is the result of:
    ///      keccak256(
    ///         \x19\x01 ||
    ///         this.domainSeparator ||
    ///         hashStruct(UniswapMinimalDelegationMessage({ hash: `hash`}))
    ///      )
    ///
    /// @param hash The original hash.
    ///
    /// @return The corresponding replay-safe hash.
    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return _hashTypedData(hash);
    }

    /// @notice Validates the `signature` against the given `hash`.
    ///
    /// @dev MUST be defined by the implementation.
    ///
    /// @param hash      The hash whose signature has been performed on.
    /// @param signature The signature associated with `hash`.
    ///
    /// @return `true` is the signature is valid, else `false`.
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual returns (bool);
}

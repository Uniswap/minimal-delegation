// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @title INonceManager
/// @notice Interface for managing nonces used to prevent replay attacks
/// @dev Each nonce consists of a 192-bit key and 64-bit sequence number
///      The key allows multiple independent nonce sequences
///      The sequence must be used in order (0, 1, 2, etc) for each key
interface INonceManager {
    /// @notice The error emitted when a nonce is invalid
    error InvalidNonce();

    /// @notice Returns the next valid nonce for a given sequence key
    /// @param key The sequence key (upper 192 bits of the nonce)
    /// @return nonce A 256-bit nonce composed of:
    ///               - Upper 192 bits: the provided key
    ///               - Lower 64 bits: the expected sequence number for this key
    function getNonce(uint192 key) external view returns (uint256 nonce);
}

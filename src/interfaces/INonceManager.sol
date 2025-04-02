// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @title INonceManager
/// @notice Interface for managing nonces used to prevent replay attacks
/// @dev Each nonce consists of a 192-bit key and 64-bit sequence number
///      The key allows multiple independent nonce sequences
///      The sequence must be used in order (0, 1, 2, etc) for each key
interface INonceManager {
    /// @notice The event emitted when a nonce is invalidated
    event NonceInvalidated(uint256 nonce);

    /// @notice The error emitted when a nonce is invalid
    error InvalidNonce();

    /// @notice The error emitted when too many nonces are invalidated in one transaction
    error ExcessiveInvalidation();

    /// @notice Returns the next valid nonce for a given sequence key
    /// @param key The sequence key (passed as uint256 but only upper 192 bits are used)
    /// @return nonce A 256-bit nonce composed of:
    ///               - Upper 192 bits: the provided key (truncated to 192 bits)
    ///               - Lower 64 bits: the expected sequence number for this key
    function getNonce(uint256 key) external view returns (uint256 nonce);

    /// @notice Invalidates all sequence numbers for a given key up to but not including the provided sequence number in the nonce
    /// @param newNonce The new nonce to set. Invalidates all sequence numbers for the key less than it.
    function invalidateNonce(uint256 newNonce) external;
}

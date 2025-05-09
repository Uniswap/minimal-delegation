// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IEIP712
interface IEIP712 {
    /// @notice Encode the EIP-5267 domain into bytes
    /// @dev for use in ERC-7739
    function domainBytes() external view returns (bytes memory);

    /// @notice Returns the `domainSeparator` used to create EIP-712 compliant hashes.
    /// @return The 32 bytes domain separator result.
    function domainSeparator() external view returns (bytes32);

    /// @notice Public getter for `_hashTypedData()` to produce a EIP-712 hash using this account's domain separator
    /// @param hash The nested typed data. Assumes the hash is the result of applying EIP-712 `hashStruct`.
    function hashTypedData(bytes32 hash) external view returns (bytes32);

    /// @notice Set the salt for the EIP-712 domain
    /// @dev Use this to invalidate all existing signatures made under the old domain separator
    /// @param salt The salt to set
    function setSalt(bytes32 salt) external;
}

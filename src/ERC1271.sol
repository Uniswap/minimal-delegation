// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC1271} from "./interfaces/IERC1271.sol";
import {BaseAuthorization} from "./BaseAuthorization.sol";

/// @title ERC-1271
/// @notice Abstract ERC1271 implementation which supports nested EIP-712 workflows as defined by ERC-7739
abstract contract ERC1271 is IERC1271, BaseAuthorization {
    /// @dev Returns whether the caller is considered safe, such
    /// that we don't need to use the nested EIP-712 workflow as defined by ERC-7739
    mapping(address => bool) public erc1271CallerIsSafe;

    /// @dev The magic value returned by `isValidSignature()` if the signature is valid.
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    /// @dev The magic value returned by `isValidSignature()` if the signature is invalid.
    bytes4 internal constant _1271_INVALID_VALUE = 0xffffffff;

    /// @dev Sets whether the caller is considered safe to skip the nested EIP-712 workflow
    function setERC1271CallerIsSafe(address caller, bool isSafe) external onlyThis {
        erc1271CallerIsSafe[caller] = isSafe;
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4);
}

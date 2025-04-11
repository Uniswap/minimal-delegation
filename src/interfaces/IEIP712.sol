// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

/// @title IEIP712
interface IEIP712 {
    function domainSeparator() external view returns (bytes32);
    function hashTypedData(bytes32 hash) external view returns (bytes32);
}

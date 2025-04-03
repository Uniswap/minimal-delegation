// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC7201 {
    function namespaceAndVersion() external view returns (string memory);
    function CUSTOM_STORAGE_ROOT() external view returns (bytes32);
}

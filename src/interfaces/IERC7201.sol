// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IERC7201 {
    /// @notice Returns the namespace and version of the contract
    function namespaceAndVersion() external view returns (string memory);
    /// @notice Returns the current custom storage root of the contract
    function CUSTOM_STORAGE_ROOT() external view returns (bytes32);
}

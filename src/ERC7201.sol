// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7201} from "./interfaces/IERC7201.sol";

/// @title ERC-7201
/// @notice Public getters for the ERC7201 calculated storage root, namespace, and version
contract ERC7201 is IERC7201 {
    /// @notice The calculated storage root of the contract according to ERC7201
    /// @dev The literal value is used in CaliburEntry.sol as it must be constant at compile time
    /// equivalent to keccak256(abi.encode(uint256(keccak256("Uniswap.Calibur.1.0.0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant CUSTOM_STORAGE_ROOT = 0x3b86514c5c56b21f08d8e56ab090292e07c2483b3e667a2a45849dcb71368600;

    /// @notice Returns the namespace and version of the contract
    function namespaceAndVersion() external pure returns (string memory) {
        return "Uniswap.Calibur.1.0.0";
    }
}

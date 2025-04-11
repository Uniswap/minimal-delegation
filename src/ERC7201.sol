// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7201} from "./interfaces/IERC7201.sol";

/// @title ERC-7201
/// @notice Public getters for the ERC7201 calculated storage root, namespace, and version
contract ERC7201 is IERC7201 {
    /// @notice The calculated storage root of the contract according to ERC7201
    /// @dev The literal value is used in MinimalDelegationEntry.sol as it must be constant at compile time
    /// equivalent to keccak256(abi.encode(uint256(keccak256("Uniswap.MinimalDelegation.1.0.0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant CUSTOM_STORAGE_ROOT = 0xc807f46cbe2302f9a007e47db23c8af6a94680c1d26280fb9582873dbe5c9200;

    /// @notice Returns the namespace and version of the contract
    function namespaceAndVersion() external pure returns (string memory) {
        return "Uniswap.MinimalDelegation.1.0.0";
    }
}

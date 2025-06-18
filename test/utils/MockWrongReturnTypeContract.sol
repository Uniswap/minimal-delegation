// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BaseAuthorization} from "../../src/BaseAuthorization.sol";

/// @title MockWrongReturnTypeContract
/// @dev Used for testing ERC7914 detection functionality - has transferFromNative but wrong return type
contract MockWrongReturnTypeContract is BaseAuthorization {
    
    /// @notice This function has the same signature as ERC7914's transferFromNative but returns uint256 instead of bool
    /// @dev Should cause the detector to return false since it doesn't return a valid boolean
    function transferFromNative(address, address, uint256) external pure returns (uint256) {
        // Return a non-boolean value (like 42)
        return 42;
    }
} 
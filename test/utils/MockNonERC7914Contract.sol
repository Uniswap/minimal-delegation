// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BaseAuthorization} from "../../src/BaseAuthorization.sol";

/// @title MockNonERC7914Contract
/// @notice A mock contract that implements BaseAuthorization but NOT ERC7914
/// @dev Used for testing ERC7914 detection functionality
contract MockNonERC7914Contract is BaseAuthorization {
    
    mapping(address => uint256) public someOtherAllowance;
    
    constructor() {
        // No initialization needed for BaseAuthorization
    }
    
    /// @notice A function that exists but is not part of ERC7914
    function setSomeAllowance(address spender, uint256 amount) external onlyThis {
        someOtherAllowance[spender] = amount;
    }
    
    /// @notice Another non-ERC7914 function
    function transferSomeTokens(address to, uint256 amount) external onlyThis returns (bool) {
        // Mock implementation - doesn't actually transfer anything
        emit MockTransfer(address(this), to, amount);
        return true;
    }
    
    /// @notice Receive function to accept ETH
    receive() external payable {}
    
    /// @notice Fallback function
    fallback() external payable {}
    
    event MockTransfer(address indexed from, address indexed to, uint256 value);
} 
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title MockSameErrorContract
/// @notice A mock contract that has the same Unauthorized error selector but doesn't implement ERC7914
/// @dev Used for testing false positive detection in ERC7914FunctionDetector
contract MockSameErrorContract {
    
    /// @notice Same error name as BaseAuthorization.Unauthorized() - same selector (0x82b42900)
    error Unauthorized();
    
    /// @notice A function with same parameter types as approveNative but different name
    function someOtherFunction(address spender, uint256 amount) external pure {
        // This reverts with the same error selector as BaseAuthorization.Unauthorized()
        revert Unauthorized();
    }
    
    /// @notice Another function to make this look like a real contract
    function doSomething() external pure returns (bool) {
        return true;
    }
    
    /// @notice Receive function to accept ETH
    receive() external payable {}
    
    /// @notice Fallback function that just reverts
    fallback() external payable {
        revert("Function not found");
    }
} 
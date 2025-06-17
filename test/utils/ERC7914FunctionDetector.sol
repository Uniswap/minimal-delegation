// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "../../src/interfaces/IERC7914.sol";

contract ERC7914FunctionDetector {
    
    address public immutable caliburAddress;
    constructor(address _caliburAddress) {
        caliburAddress = _caliburAddress;
    }

    /**
     * @notice Check if a wallet supports ERC7914 by testing for approveNative function
     * @param wallet The wallet address to check
     * @return hasERC7914Support true if ERC7914 is supported, false otherwise
     */
    function hasERC7914Support(address wallet) external view returns (bool) {
        // Check if the wallet is Calibur
        if (wallet == caliburAddress) {
            return true;
        }

        // EOAs cannot support ERC7914
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(wallet)
        }
        if (codeSize == 0) {
            return false;
        }

        // Check if approveNative function exists
        return _checkApproveNative(wallet);
    }

    function _checkApproveNative(address wallet) private view returns (bool) {
        // Check if the function selector exists by examining the contract bytecode
        // Since approveNative requires authorization, we can't call it directly
        bytes4 selector = IERC7914.approveNative.selector;
        
        // Use low-level call to check if function exists
        (bool success, bytes memory returnData) = wallet.staticcall(
            abi.encodeWithSelector(selector, address(0), 0)
        );
        
        // If the call succeeded and returned a boolean, the function exists
        if (success && returnData.length == 32) {
            return true;
        }
        
        // If it fails due to authorization (Unauthorized error), the function exists
        if (!success && returnData.length >= 4) {
            bytes4 errorSelector = bytes4(returnData);
            // Check for BaseAuthorization.Unauthorized() selector: 0x82b42900
            if (errorSelector == 0x82b42900) {
                return true; // Function exists but unauthorized
            }
        }
        
        // If the call succeeded but returned empty data (from fallback), function doesn't exist
        if (success && returnData.length == 0) {
            return false;
        }
        
        return false; // Default to function not existing
    }
} 
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "../../src/interfaces/IERC7914.sol";

contract ERC7914FunctionDetector {
    
    // EIP-7702 constants from account-abstraction library
    bytes3 internal constant EIP7702_PREFIX = 0xef0100;
    
    // EIP-7702 bytecode structure: 3 bytes prefix + 20 bytes delegate address = 23 bytes total
    uint256 internal constant EIP7702_BYTECODE_SIZE = 23;
    
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

        // EOAs cannot support ERC7914
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(wallet)
        }
        if (codeSize == 0) {
            return false;
        }

        // Check if this is an EIP-7702 wallet delegating to Calibur
        if (_isEip7702Delegate(wallet)) {
            address delegate = _getEip7702Delegate(wallet);
            // If it delegates to Calibur, it has ERC7914 support
            if (delegate == caliburAddress) {
                return true;
            }
            // If it delegates to another contract, check that contract
            return _checkApproveNative(delegate);
        }

        // For regular contracts, check if approveNative function exists
        return _checkApproveNative(wallet);
    }

    /**
     * @notice Get the EIP-7702 bytecode from contract (prefix + delegate address)
     * @param wallet The wallet address to read from
     * @return code The first 23 bytes of bytecode (3 byte prefix + 20 byte delegate)
     */
    function _getContractCode(address wallet) private view returns (bytes32 code) {
        assembly ("memory-safe") {
            extcodecopy(wallet, 0, 0, EIP7702_BYTECODE_SIZE)
            code := mload(0)
        }
    }

    /**
     * @notice Check if an address is an EIP-7702 wallet
     * @param wallet The wallet address to check
     * @return true if it's an EIP-7702 wallet, false otherwise
     */
    function _isEip7702Delegate(address wallet) private view returns (bool) {
        if (wallet.code.length < EIP7702_BYTECODE_SIZE) return false;
        return bytes3(_getContractCode(wallet)) == EIP7702_PREFIX;
    }

    /**
     * @notice Get the delegate address from an EIP-7702 wallet
     * @param wallet The EIP-7702 wallet address
     * @return delegate The delegate contract address
     */
    function _getEip7702Delegate(address wallet) private view returns (address) {
        bytes32 code = _getContractCode(wallet);
        return address(bytes20(code << 24));
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
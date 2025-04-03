// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC4337Account} from "./interfaces/IERC4337Account.sol";

abstract contract ERC4337Account is IERC4337Account {
    uint256 internal constant SIG_VALIDATION_SUCCEEDED = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant ENTRY_POINT_SET = 1 << 255;

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT()) revert NotEntryPoint();
        _;
    }

    // https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol#L100
    function _payEntryPoint(uint256 missingAccountFunds) internal {
        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    function ENTRY_POINT() public view virtual returns (address);

    /// @notice Packs the entry point into a uint256.
    /// @dev Set the most significant bit to 1 to indicate that the entrypoint has been set by the user.
    function _packEntryPoint(address entryPoint) internal pure returns (uint256) {
        return uint256(uint160(entryPoint)) | ENTRY_POINT_SET;
    }

    /// @notice Checks if the entry point has been set by the user.
    function _isEntryPointSet(uint256 packedEntryPoint) internal pure returns (bool) {
        return packedEntryPoint & ENTRY_POINT_SET != 0;
    }
}

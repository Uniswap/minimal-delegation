// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC4337Account} from "./interfaces/IERC4337Account.sol";

abstract contract ERC4337Account is IERC4337Account {
    uint256 internal constant SIG_VALIDATION_SUCCEEDED = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    modifier onlyEntryPoint() {
        /// By default, the entry point is the zero address, so this is not an enabled feature.
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
}

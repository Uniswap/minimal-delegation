// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {Static} from "./libraries/Static.sol";
import {EntrypointLib} from "./libraries/EntrypointLib.sol";
import {BaseAuthorization} from "./BaseAuthorization.sol";

/// @title ERC4337Account
/// @notice A base contract which allows for the entrypoint to have a default value that can be updated
abstract contract ERC4337Account is IERC4337Account, BaseAuthorization {
    using EntrypointLib for *;

    /// ERC-4337 defined constants
    uint256 internal constant SIG_VALIDATION_SUCCEEDED = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice The cached entrypoint address
    uint256 internal _CACHED_ENTRYPOINT;

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT()) revert NotEntryPoint();
        _;
    }

    /// @inheritdoc IERC4337Account
    function updateEntryPoint(address entryPoint) external onlyThis {
        _CACHED_ENTRYPOINT = entryPoint.pack();
        emit EntryPointUpdated(entryPoint);
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        return _CACHED_ENTRYPOINT.isOverriden() ? _CACHED_ENTRYPOINT.unpack() : Static.ENTRY_POINT_V_0_8;
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
}

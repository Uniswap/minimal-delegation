// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IHook} from "../interfaces/IHook.sol";

type Settings is uint256;

/// The most significant 8 bits are reserved to specify if the key is an admin key or not. An admin key is allowed to self-call.
/// The least significant 160 bits specify an address to callout to for extra or overrideable validation.
///  6 bytes |   1 byte       | 5 bytes           | 20 bytes
//   UNUSED  |   isAdmin      | expiration        | VALIDATION_ADDRESS
library SettingsLib {
    uint160 constant MASK_20_BYTES = uint160(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);
    uint40 constant MASK_5_BYTES = uint40(0xFFFFFFFFFF);

    Settings constant DEFAULT = Settings.wrap(0);

    function isAdmin(Settings settings) internal pure returns (bool _isAdmin) {
        assembly {
            _isAdmin := shr(200, settings)
        }
    }

    function expiration(Settings settings) internal pure returns (uint40 _expiration) {
        uint40 mask = MASK_5_BYTES;
        assembly {
            _expiration := and(shr(160, settings), mask)
        }
    }

    function hook(Settings settings) internal pure returns (IHook _hook) {
        uint256 mask = MASK_20_BYTES;
        assembly {
            _hook := and(settings, mask)
        }
    }
}

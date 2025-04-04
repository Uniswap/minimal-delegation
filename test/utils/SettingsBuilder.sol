// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";
import {IHook} from "../../src/interfaces/IHook.sol";

library SettingsBuilder {
    using SettingsLib for Settings;

    uint256 constant CLEAR_20_BYTES = uint256(0xFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000);
    uint256 constant CLEAR_5_BYTES = uint256(0xFFFFFFFFFFFFFF0000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    uint256 constant CLEAR_1_BYTE = uint256(0xFFFFFFFFFFFF00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);

    function init() internal pure returns (Settings) {
        return Settings.wrap(0);
    }

    function fromExpiration(Settings settings, uint40 expiration) internal pure returns (Settings) {
        uint256 _settings = (Settings.unwrap(settings) & CLEAR_5_BYTES) | (uint256(expiration) << 160);
        return Settings.wrap(_settings);
    }

    function fromHook(Settings settings, IHook hook) internal pure returns (Settings) {
        uint160 hookAddress = uint160(address(hook));
        uint256 _settings = (Settings.unwrap(settings) & CLEAR_20_BYTES) | uint256(hookAddress);
        return Settings.wrap(_settings);
    }

    function fromIsAdmin(Settings settings, bool isAdmin) internal pure returns (Settings) {
        uint8 _isAdmin = isAdmin ? 1 : 0;
        uint256 _settings = (Settings.unwrap(settings) & CLEAR_1_BYTE) | (uint256(_isAdmin)) << 200;
        return Settings.wrap(_settings);
    }
}

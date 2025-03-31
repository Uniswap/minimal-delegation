// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

library TopLevelAuthorizedCallerLib {
    // The slot calculated using: bytes32(uint256(keccak256("TopLevelAuthorizedCallerLib")) - 1)
    bytes32 constant TOP_LEVEL_AUTHORIZED_CALLER_SLOT =
        0x439f08ae85300081a6537c1e26be3bbc547f38ffd92f3330bf97ace7fd1d0eab;

    function set(bytes32 _topLevelAuthorizedCaller) internal {
        assembly ("memory-safe") {
            tstore(TOP_LEVEL_AUTHORIZED_CALLER_SLOT, _topLevelAuthorizedCaller)
        }
    }

    function get() internal view returns (address _topLevelAuthorizedCaller) {
        assembly ("memory-safe") {
            _topLevelAuthorizedCaller := tload(TOP_LEVEL_AUTHORIZED_CALLER_SLOT)
        }
    }
}

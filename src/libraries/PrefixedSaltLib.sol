// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library PrefixedSaltLib {
    // Mask to extract the lower 160 bits (size of an address)
    uint256 constant MASK_160_BITS = type(uint160).max;

    function pack(uint96 prefix, address implementation) internal pure returns (bytes32) {
        return bytes32((uint256(prefix) << 160) | uint160(implementation));
    }

    function update(bytes32 salt, uint96 prefix) internal pure returns (bytes32) {
        return bytes32((uint256(prefix) << 160) | (uint256(salt) & MASK_160_BITS));
    }
}

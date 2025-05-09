// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PrefixedSaltLib} from "../../src/libraries/PrefixedSaltLib.sol";

/// @title MockPrefixedSaltLib
/// @notice Mock implementation of PrefixedSaltLib for testing purposes
contract MockPrefixedSaltLib {
    function pack(uint96 prefix, address implementation) public pure returns (bytes32) {
        return PrefixedSaltLib.pack(prefix, implementation);
    }

    /// Testing function for unpacking
    function unpack(bytes32 prefixedSalt) public pure returns (uint96 prefix, address implementation) {
        uint256 value = uint256(prefixedSalt);
        prefix = uint96(value >> 160);
        implementation = address(uint160(value));
    }
}

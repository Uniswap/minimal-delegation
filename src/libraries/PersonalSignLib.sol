// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library PersonalSignLib {
    bytes private constant PERSONAL_SIGN_TYPE = "PersonalSign(bytes prefixed)";
    bytes32 private constant PERSONAL_SIGN_TYPEHASH = keccak256(PERSONAL_SIGN_TYPE);

    function hash(bytes memory contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(PERSONAL_SIGN_TYPEHASH, contents));
    }
}

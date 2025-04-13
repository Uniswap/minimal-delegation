// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library PersonalSignLib {
    bytes private constant PERSONAL_SIGN_TYPE = "PersonalSign(bytes prefixed)";
    bytes32 private constant PERSONAL_SIGN_TYPEHASH = keccak256(PERSONAL_SIGN_TYPE);

    /// @notice We don't care how the hash was computed for personal sign, and it does not match the typestring above
    /// i.e.  keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
    function hash(bytes32 message) internal pure returns (bytes32) {
        return keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, message));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title PersonalSignLib
/// @notice Library for hashing nested personal sign messages per ERC-7739
library PersonalSignLib {
    bytes private constant PERSONAL_SIGN_TYPE = "PersonalSign(bytes prefixed)";
    bytes32 private constant PERSONAL_SIGN_TYPEHASH = keccak256(PERSONAL_SIGN_TYPE);

    /// @notice The message is computed offchain
    /// i.e.  keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
    /// @dev `prefixed` is a `bytes` type but you can only pass in `bytes32` to ERC-1271
    function hash(bytes32 message) internal pure returns (bytes32) {
        return keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, message));
    }
}

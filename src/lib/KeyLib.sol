// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @dev The type of key.
enum KeyType {
    P256,
    WebAuthnP256,
    Secp256k1
}

struct Key {
    /// @dev Unix timestamp at which the key expires (0 = never).
    uint40 expiry;
    /// @dev Type of key. See the {KeyType} enum.
    KeyType keyType;
    /// @dev Whether the key is a super admin key.
    /// Super admin keys are allowed to execute any external call
    bool isSuperAdmin;
    /// @dev Public key in encoded form.
    bytes publicKey;
}

library KeyLib {
    function hash(Key memory key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key.keyType, keccak256(key.publicKey)));
    }
}

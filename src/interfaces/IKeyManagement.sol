// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IKeyManagement {
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
        /// Super admin keys are allowed to call into super admin functions such as
        /// `authorize` and `revoke` via `execute`.
        bool isSuperAdmin;
        /// @dev Public key in encoded form.
        bytes publicKey;
    }

    function authorize(Key memory key) external returns (bytes32 keyHash);
    function revoke(bytes32 keyHash) external;
    function keyCount() external view returns (uint256);
    function keyAt(uint256 i) external view returns (Key memory);
    function getKey(bytes32 keyHash) external view returns (Key memory key);
}

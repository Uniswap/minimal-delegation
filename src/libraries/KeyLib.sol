// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

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

    /// @notice A helper function to get the root key object.
    function toRootKey() internal view returns (Key memory) {
        return Key({expiry: 0, keyType: KeyType.Secp256k1, isSuperAdmin: true, publicKey: abi.encode(address(this))});
    }

    function verify(Key memory key, bytes32 _hash, bytes calldata signature) internal view returns (bool isValid) {
        if (key.keyType == KeyType.Secp256k1) {
            isValid = ECDSA.recoverCalldata(_hash, signature) == abi.decode(key.publicKey, (address));
        } else if (key.keyType == KeyType.P256) {
            // Extract x,y from the public key
            (bytes32 x, bytes32 y) = abi.decode(key.publicKey, (bytes32, bytes32));
            // Split signature into r and s values.
            (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
            isValid = P256.verify(_hash, r, s, x, y);
        } else if (key.keyType == KeyType.WebAuthnP256) {
            (uint256 x, uint256 y) = abi.decode(key.publicKey, (uint256, uint256));
            // Expect signature to be a wrapper of the WebAuthn signature.
            WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));

            isValid = WebAuthn.verify({challenge: abi.encode(_hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        } else {
            isValid = false;
        }
    }
}

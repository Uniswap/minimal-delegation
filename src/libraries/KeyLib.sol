// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {Settings, SettingsLib} from "./SettingsLib.sol";

/// @dev The type of key.
enum KeyType {
    P256,
    WebAuthnP256,
    Secp256k1
}

struct Key {
    /// @dev Type of key. See the {KeyType} enum.
    KeyType keyType;
    /// @dev Public key in encoded form.
    bytes publicKey;
}

library KeyLib {
    function hash(Key memory key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key.keyType, keccak256(key.publicKey)));
    }

    /// @notice A helper function to get the root key object.
    function toRootKey() internal view returns (Key memory) {
        return Key({keyType: KeyType.Secp256k1, publicKey: abi.encode(address(this))});
    }

    function verify(Key memory key, bytes32 _hash, bytes memory signature) internal view returns (bool isValid) {
        if (key.keyType == KeyType.Secp256k1) {
            isValid = ECDSA.recover(_hash, signature) == abi.decode(key.publicKey, (address));
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

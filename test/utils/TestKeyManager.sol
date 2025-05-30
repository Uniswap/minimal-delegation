// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {KeyType, Key, KeyLib} from "../../src/libraries/KeyLib.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {Utils, WebAuthnInfo} from "webauthn-sol/test/Utils.sol";
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ISignatureTransfer} from "../../lib/permit2/src/interfaces/ISignatureTransfer.sol";
import {Permit2Utils} from "./Permit2Utils.sol";

struct TestKey {
    KeyType keyType;
    bytes publicKey;
    // saved to sign messages
    uint256 privateKey;
}

library TestKeyManager {
    using KeyLib for Key;

    error KeyNotSupported();

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // 0 = never expires
    uint40 internal constant DEFAULT_KEY_EXPIRY = 0;
    uint256 internal constant DEFAULT_SECP256R1_PK = uint256(keccak256("DEFAULT_SECP256R1_PK"));
    uint256 internal constant DEFAULT_SECP256K1_PK = uint256(keccak256("DEFAULT_SECP256K1_PK"));

    // Example webauthn key from Coinbase Smart Wallet
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PK =
        uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PUBLIC_X =
        12_673_873_082_346_130_924_691_454_452_779_514_193_164_883_897_088_292_420_374_917_853_190_248_779_330;
    uint256 internal constant DEFAULT_WEBAUTHN_P256_PUBLIC_Y =
        18_542_991_761_951_108_740_563_055_453_066_386_026_290_576_689_311_603_472_268_584_080_832_751_656_013;

    // Return a Key initialized from the default constants based on the key type.
    function initDefault(KeyType keyType) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(DEFAULT_SECP256R1_PK);
            return TestKey({keyType: keyType, publicKey: abi.encode(x, y), privateKey: DEFAULT_SECP256R1_PK});
        } else if (keyType == KeyType.Secp256k1) {
            address defaultAddress = vm.addr(DEFAULT_SECP256K1_PK);
            return TestKey({keyType: keyType, publicKey: abi.encode(defaultAddress), privateKey: DEFAULT_SECP256K1_PK});
        } else if (keyType == KeyType.WebAuthnP256) {
            return TestKey({
                keyType: keyType,
                publicKey: abi.encode(DEFAULT_WEBAUTHN_P256_PUBLIC_X, DEFAULT_WEBAUTHN_P256_PUBLIC_Y),
                privateKey: DEFAULT_WEBAUTHN_P256_PK
            });
        } else {
            revert KeyNotSupported();
        }
    }

    // Create a public key derived from a seed.
    /// @dev This does not support WebAuthnP256 keys.
    function withSeed(KeyType keyType, uint256 seed) internal pure returns (TestKey memory) {
        if (keyType == KeyType.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(seed);
            return TestKey({keyType: keyType, publicKey: abi.encode(x, y), privateKey: seed});
        } else if (keyType == KeyType.Secp256k1) {
            address addr = vm.addr(seed);
            return TestKey({keyType: keyType, publicKey: abi.encode(addr), privateKey: seed});
        } else {
            revert KeyNotSupported();
        }
    }

    /// @dev Signatures from P256 are over the `sha256` hash of `_hash`
    function sign(TestKey memory key, bytes32 hash) internal view returns (bytes memory) {
        if (key.keyType == KeyType.P256) {
            (bytes32 r, bytes32 s) = vm.signP256(key.privateKey, EfficientHashLib.sha2(hash));
            return abi.encodePacked(r, s);
        } else if (key.keyType == KeyType.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key.privateKey, hash);
            return abi.encodePacked(r, s, v);
        } else if (key.keyType == KeyType.WebAuthnP256) {
            WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(hash);
            (bytes32 r, bytes32 s) = vm.signP256(key.privateKey, webAuthn.messageHash);
            return abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: uint256(r),
                    s: uint256(s)
                })
            );
        } else {
            revert KeyNotSupported();
        }
    }

    /// @dev Signs a permit2 transfer message
    /// @param key The key to sign with
    /// @param permit The permit data to sign
    /// @param typehash The typehash to use (0 for default PERMIT_TRANSFER_FROM_TYPEHASH)
    /// @param witness Optional witness data to include in the signature
    /// @param domainSeparator The domain separator for the permit2 contract
    /// @param spender The spender address
    function signPermitTransfer(
        TestKey memory key,
        ISignatureTransfer.PermitTransferFrom memory permit,
        bytes32 typehash,
        bytes32 witness,
        bytes32 domainSeparator,
        address spender
    ) internal view returns (bytes memory) {
        if (typehash == bytes32(0)) {
            typehash = Permit2Utils.PERMIT_TRANSFER_FROM_TYPEHASH;
        }

        bytes32 tokenPermissions = keccak256(abi.encode(Permit2Utils.TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        Permit2Utils.PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, spender, permit.nonce, permit.deadline
                    )
                )
            )
        );

        if (witness != bytes32(0)) {
            msgHash = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeparator,
                    keccak256(abi.encode(typehash, tokenPermissions, spender, permit.nonce, permit.deadline, witness))
                )
            );
        }

        return sign(key, msgHash);
    }

    function toKey(TestKey memory key) internal pure returns (Key memory) {
        return Key({keyType: key.keyType, publicKey: key.publicKey});
    }

    function toKeyHash(TestKey memory key) internal pure returns (bytes32) {
        return toKey(key).hash();
    }
}

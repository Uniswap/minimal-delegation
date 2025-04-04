// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegation} from "../src/MinimalDelegation.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {HookHandler} from "./utils/HookHandler.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {TestKeyManager} from "./utils/TestKeyManager.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";

contract MinimalDelegationIsValidSignatureTest is DelegationHandler, HookHandler {
    using TestKeyManager for TestKey;
    using WrappedDataHash for bytes32;
    using SettingsBuilder for Settings;

    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

    function setUp() public {
        setUpDelegation();
        setUpHooks();
    }

    function test_isValidSignature_P256_isValid() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = p256Key.sign(testDigestToSign);

        vm.prank(address(signer));
        signerAccount.register(p256Key.toKey());

        bytes4 result = signerAccount.isValidSignature(testDigest, abi.encode(p256Key.toKeyHash(), signature));
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_WebAuthnP256_isValid() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = webAuthnP256Key.sign(testDigestToSign);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes4 result = signerAccount.isValidSignature(testDigest, abi.encode(webAuthnP256Key.toKeyHash(), signature));
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_isValid() public view {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data.hashWithWrappedType());

        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);
        bytes memory signature = key.sign(hashTypedData);

        // ensure the call returns the ERC1271 magic value
        assertEq(signerAccount.isValidSignature(data, signature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_noWrappedData_invalidSigner() public view {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data);

        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);
        bytes memory signature = key.sign(hashTypedData);

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(data, signature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_WebAuthnP256_noWrappedData_invalidSigner() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);
        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data);

        bytes memory signature = webAuthnP256Key.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), signature);

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(data, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_sep256k1_invalidSigner() public view {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash.hashWithWrappedType());

        // sign with a different private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(hashTypedData);

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(hash, signature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_invalidSignatureLength_reverts() public {
        bytes32 hash = keccak256("test");
        bytes memory signature = new bytes(63);
        vm.expectRevert();
        signerAccount.isValidSignature(hash, signature);
    }

    // TODO: no test for P256 signatures without keyHash because the signatures are 64 bytes long

    function test_isValidSignature_WebAuthnP256_invalidWrappedSignatureLength_reverts() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = webAuthnP256Key.sign(testDigestToSign);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        // Don't wrap the signature with the key hash
        vm.expectRevert();
        signerAccount.isValidSignature(testDigest, signature);
    }

    function test_isValidSignature_withHook_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes32 keyHash = p256Key.toKeyHash();

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(keyHash, SettingsBuilder.init().fromHook(mockValidationHook));

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = p256Key.sign(testDigestToSign);

        mockValidationHook.setIsValidSignatureReturnValue(_1271_MAGIC_VALUE);
        assertEq(signerAccount.isValidSignature(testDigest, abi.encode(keyHash, signature)), _1271_MAGIC_VALUE);

        mockValidationHook.setIsValidSignatureReturnValue(_1271_INVALID_VALUE);
        assertEq(signerAccount.isValidSignature(testDigest, abi.encode(keyHash, signature)), _1271_INVALID_VALUE);
    }
}

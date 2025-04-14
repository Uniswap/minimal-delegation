// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {HookHandler} from "./utils/HookHandler.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {TestKeyManager} from "./utils/TestKeyManager.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";
import {IValidationHook} from "../src/interfaces/IValidationHook.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {KeyLib} from "../src/libraries/KeyLib.sol";

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

        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);
        bytes4 result = signerAccount.isValidSignature(testDigest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_WebAuthnP256_isValid() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = webAuthnP256Key.sign(testDigestToSign);
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes4 result = signerAccount.isValidSignature(testDigest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_rootKey_isValid() public view {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data.hashWithWrappedType());

        bytes memory signature = signerTestKey.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        // ensure the call returns the ERC1271 magic value
        assertEq(signerAccount.isValidSignature(data, wrappedSignature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_expiredKey() public {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data.hashWithWrappedType());

        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, 0xb0b);
        bytes memory signature = key.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(key.toKey());
        signerAccount.update(key.toKeyHash(), keySettings);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        signerAccount.isValidSignature(data, wrappedSignature);
    }

    function test_isValidSignature_P256_expiredKey() public {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data.hashWithWrappedType());

        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes memory signature = p256Key.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(p256Key.toKeyHash(), keySettings);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        signerAccount.isValidSignature(data, wrappedSignature);
    }

    function test_isValidSignature_rootKey_noWrappedData_invalidSigner() public view {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data);

        bytes memory signature = signerTestKey.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(data, wrappedSignature), _1271_INVALID_VALUE);
    }

    /// @dev Because the signature is invalid,
    /// - we do not check expiry
    /// - we do not call the hook
    function test_isValidSignature_P256_invalidSigner_isExpired_returns_InvalidMagicValue() public {
        bytes32 data = keccak256("test");
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        bytes memory signature = p256Key.sign(bytes32(0));
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        // Set the key to expired
        vm.warp(100);
        Settings keySettings =
            SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1)).fromHook(mockValidationHook);

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(p256Key.toKeyHash(), keySettings);

        // Mock the hook return value to true, check that it isn't called
        mockValidationHook.setIsValidSignatureReturnValue(_1271_MAGIC_VALUE);
        vm.stopPrank();

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(data, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_WebAuthnP256_noWrappedData_invalidSigner() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);
        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data);

        bytes memory signature = webAuthnP256Key.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(data, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_validSep256k1_reverts_keyDoesNotExist() public {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash.hashWithWrappedType());

        // sign with an unregistered private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(hashTypedData);
        bytes memory wrappedSignature = abi.encode(invalidSigner.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        signerAccount.isValidSignature(hash, wrappedSignature);
    }

    function test_isValidSignature_sep256k1_invalidWrappedSignature_invalidSigner() public view {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash.hashWithWrappedType());

        // sign with a different private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(hashTypedData);
        // trying to spoof the root key hash still fails
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);

        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(hash, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_invalidSignatureLength_reverts() public {
        bytes32 hash = keccak256("test");
        bytes memory signature = new bytes(63);
        vm.expectRevert();
        signerAccount.isValidSignature(hash, abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA));
    }

    function test_isValidSignature_WebAuthnP256_invalidWrappedSignatureLength_reverts() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = webAuthnP256Key.sign(testDigestToSign);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        // Intentionally don't wrap the signature with the key hash.
        vm.expectRevert();
        signerAccount.isValidSignature(testDigest, signature);
    }

    function test_isValidSignature_withHook_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes32 keyHash = p256Key.toKeyHash();

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(keyHash, SettingsBuilder.init().fromHook(mockHook));

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = p256Key.sign(testDigestToSign);
        bytes memory wrappedSignature = abi.encode(keyHash, signature, EMPTY_HOOK_DATA);

        mockHook.setIsValidSignatureReturnValue(_1271_MAGIC_VALUE);
        assertEq(signerAccount.isValidSignature(testDigest, wrappedSignature), _1271_MAGIC_VALUE);

        mockHook.setIsValidSignatureReturnValue(_1271_INVALID_VALUE);
        assertEq(signerAccount.isValidSignature(testDigest, wrappedSignature), _1271_INVALID_VALUE);
    }
}

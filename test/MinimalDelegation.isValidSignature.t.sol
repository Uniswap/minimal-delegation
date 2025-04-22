// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {HookHandler} from "./utils/HookHandler.sol";
import {ERC1271Handler} from "./utils/ERC1271Handler.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {TestKeyManager} from "./utils/TestKeyManager.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";
import {IValidationHook} from "../src/interfaces/IValidationHook.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {KeyLib} from "../src/libraries/KeyLib.sol";
import {TypedDataSignBuilder} from "./utils/TypedDataSignBuilder.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalDelegationIsValidSignatureTest is DelegationHandler, HookHandler, ERC1271Handler {
    using TestKeyManager for TestKey;
    using SettingsBuilder for Settings;
    using TypedDataSignBuilder for *;

    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;
    bytes4 private constant _ERC7739_MAGIC_VALUE = 0x77390001;
    bytes32 private constant _ERC7739_HASH = 0x7739773977397739773977397739773977397739773977397739773977397739;

    // Test hashed TypedDataSign digest
    bytes32 TEST_TYPED_DATA_SIGN_DIGEST;

    function setUp() public {
        setUpDelegation();
        setUpHooks();
        setUpERC1271();
        // Set after delegation
        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        TEST_TYPED_DATA_SIGN_DIGEST = TEST_CONTENTS_HASH.hashTypedDataSign(
            signerAccountDomainBytes, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_DESCR
        );
    }

    function test_isValidSignature_ERC7739_magicValue() public view {
        bytes4 result = signerAccount.isValidSignature(_ERC7739_HASH, "");
        assertEq(result, _ERC7739_MAGIC_VALUE);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_P256_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        vm.prank(address(signer));
        signerAccount.register(p256Key.toKey());

        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // Digest is what is calculated by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_P256");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_WebAuthnP256_isValid_gas() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes memory signature = webAuthnP256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_WebAuthnP256");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_rootKey_isValid_gas() public {
        bytes memory signature = signerTestKey.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);
        // ensure the call returns the ERC1271 magic value
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_rootKey");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_expiredKey() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, 0xb0b);
        bytes memory signature = key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(key.toKey());
        signerAccount.update(key.toKeyHash(), keySettings);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        vm.prank(address(mockERC1271VerifyingContract));
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_P256_expiredKey() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(p256Key.toKeyHash(), keySettings);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        vm.prank(address(mockERC1271VerifyingContract));
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_rootKey_notNested_invalidSigner() public {
        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        // This is unsafe to sign because `digest` is not nested within a TypedDataSign
        bytes memory signature = signerTestKey.sign(digest);
        // Still build the signature as expected to pass in memory abi decoding
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);

        // ensure the call returns the ERC1271 invalid magic value
        vm.prank(address(mockERC1271VerifyingContract));
        assertEq(signerAccount.isValidSignature(digest, wrappedSignature), _1271_INVALID_VALUE);
    }

    /// @dev Because the signature is invalid,
    /// - we do not check expiry
    /// - we do not call the hook
    function test_isValidSignature_P256_invalidSigner_isExpired_returns_InvalidMagicValue() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // Set the key to expired
        vm.warp(100);
        Settings keySettings =
            SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1)).fromHook(mockValidationHook);

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(p256Key.toKeyHash(), keySettings);

        // Mock the hook return value to true, check that it isn't called
        mockValidationHook.setIsValidSignatureReturnValue(true);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        vm.prank(address(mockERC1271VerifyingContract));
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_WebAuthnP256_notNested_invalidSigner() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);
        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        // This is unsafe to sign because `digest` is not nested within a TypedDataSign
        bytes memory signature = webAuthnP256Key.sign(digest);
        // Still build the signature as expected to pass in memory abi decoding
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // ensure the call returns the ERC1271 invalid magic value
        vm.prank(address(mockERC1271VerifyingContract));
        assertEq(signerAccount.isValidSignature(digest, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_validSep256k1_reverts_keyDoesNotExist() public {
        // sign with an unregistered private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(invalidSigner.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_sep256k1_invalidWrappedSignature_invalidSigner() public {
        // sign with a different private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        // trying to spoof the root key hash causes the signature verification to fail
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(digest, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_invalidSignatureLength_reverts() public {
        bytes32 hash = keccak256("test");
        bytes memory signature = new bytes(63);
        vm.prank(address(mockERC1271VerifyingContract));
        vm.expectRevert();
        signerAccount.isValidSignature(hash, abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA));
    }

    function test_isValidSignature_WebAuthnP256_invalidWrappedSignatureLength_reverts() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes memory signature = webAuthnP256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        // Intentionally don't wrap the signature with the key hash.
        bytes memory wrappedSignature = abi.encode(typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        vm.prank(address(mockERC1271VerifyingContract));
        vm.expectRevert();
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_withHook_succeeds_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes32 keyHash = p256Key.toKeyHash();

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(keyHash, SettingsBuilder.init().fromHook(mockHook));
        vm.stopPrank();

        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature, TEST_APP_DOMAIN_SEPARATOR, TEST_CONTENTS_HASH, TEST_CONTENTS_DESCR, uint16(bytes(TEST_CONTENTS_DESCR).length)
        );
        bytes memory wrappedSignature = abi.encode(keyHash, typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);

        mockHook.setIsValidSignatureReturnValue(true);
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_P256_withHook");
        assertEq(result, _1271_MAGIC_VALUE);

        mockHook.setIsValidSignatureReturnValue(false);
        vm.prank(address(mockERC1271VerifyingContract));
        
        vm.expectRevert();
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_rootKey_personalSign_isValid() public {
        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        bytes32 signerAccountDomainSeparator = signerAccount.domainSeparator();
        bytes32 wrappedPersonalSignDigest =
            TypedDataSignBuilder.hashWrappedPersonalSign(messageHash, signerAccountDomainSeparator);

        bytes memory signature = signerTestKey.sign(wrappedPersonalSignDigest);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        // Should return the magic value when called offchain
        vm.prank(address(0));
        bytes4 result = signerAccount.isValidSignature(messageHash, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_personalSign_notNested_isInvalid() public {
        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        // Incorrectly do personal_sign instead of over the typed PersonalSign digest
        bytes memory signature = signerTestKey.sign(messageHash);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        // Should return the invalid value when called offchain
        vm.prank(address(0));
        assertEq(signerAccount.isValidSignature(messageHash, wrappedSignature), _1271_INVALID_VALUE);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_rootKey_notNested_safeERC1271Caller_isValid_gas() public {
        // Set the caller as safe
        vm.prank(address(signerAccount));
        signerAccount.setERC1271CallerIsSafe(address(mockERC1271VerifyingContract), true);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        // This is normally an unsafe digest to sign and would result in invalid signature
        // but we set the caller as safe so expect it to be valid
        bytes memory signature = signerTestKey.sign(digest);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);

        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
        vm.snapshotGasLastCall("isValidSignature_rootKey_typedData_notNested_safeERC1271Caller");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_p256Key_notNested_safeERC1271Caller_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.setERC1271CallerIsSafe(address(mockERC1271VerifyingContract), true);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(TEST_CONTENTS_HASH);
        // This is normally an unsafe digest to sign and would result in invalid signature
        // but we set the caller as safe so expect it to be valid
        bytes memory signature = p256Key.sign(digest);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
        vm.snapshotGasLastCall("isValidSignature_P256_typedData_notNested_safeERC1271Caller");
    }
}

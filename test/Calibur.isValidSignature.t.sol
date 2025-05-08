// SPDX-License-Identifier: MIT
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
import {IERC1271} from "../src/interfaces/IERC1271.sol";
import {KeyLib} from "../src/libraries/KeyLib.sol";
import {TypedDataSignBuilder} from "./utils/TypedDataSignBuilder.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract CaliburIsValidSignatureTest is DelegationHandler, HookHandler, ERC1271Handler {
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
        // Set after delegation
        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        TEST_TYPED_DATA_SIGN_DIGEST =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appDomainSeparator, contentsName, contentsType);
    }

    /**
     *
     * MARK: ERC7739 sentinel value test
     *
     */
    function test_isValidSignature_ERC7739_magicValue() public {
        bytes4 result = signerAccount.isValidSignature(_ERC7739_HASH, "");
        assertEq(result, _ERC7739_MAGIC_VALUE);
    }

    /**
     *
     * MARK: Valid signature tests
     *
     */

    /**
     * Scenario: P256 key
     * 1. Typed data sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_P256_typedDataSign_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        vm.prank(address(signer));
        signerAccount.register(p256Key.toKey());

        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // Digest is what is calculated by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_P256_typedDataSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: WebAuthnP256 key
     * 1. Typed data sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_WebAuthnP256_typedDataSign_isValid_gas() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory signature = webAuthnP256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_WebAuthnP256_typedDataSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: Root key
     * 1. Typed data sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_rootKey_typedDataSign_isValid_gas() public {
        bytes memory signature = signerTestKey.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);
        // ensure the call returns the ERC1271 magic value
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_rootKey_typedDataSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: Non root Secp256k1 key
     * 1. Typed data sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_sep256k1_typedDataSign_isValid_gas() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, 0xb0b);
        vm.prank(address(signer));
        signerAccount.register(key.toKey());

        bytes memory signature = key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_sep256k1_typedDataSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: P256 key with hook
     * 1. Typed data sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_P256_typedDataSign_withHook_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes32 keyHash = p256Key.toKeyHash();

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(keyHash, SettingsBuilder.init().fromHook(mockHook));
        vm.stopPrank();

        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(keyHash, typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);

        mockHook.setIsValidSignatureReturnValue(true);
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_P256_withHook");
        assertEq(result, _1271_MAGIC_VALUE);

        mockHook.setIsValidSignatureReturnValue(false);
        vm.prank(address(mockERC1271VerifyingContract));

        vm.expectRevert();
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    /**
     * Scenario: Root key
     * 1. Not typed data sign
     * 2. Nested personal sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_rootKey_nestedPersonalSign_isValid_gas() public {
        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        bytes32 signerAccountDomainSeparator = signerAccount.domainSeparator();
        bytes32 wrappedPersonalSignDigest =
            TypedDataSignBuilder.hashWrappedPersonalSign(messageHash, signerAccountDomainSeparator);

        bytes memory signature = signerTestKey.sign(wrappedPersonalSignDigest);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(messageHash, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_rootKey_personalSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: P256 key
     * 1. Not typed data sign
     * 2. Nested personal sign
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_p256Key_nestedPersonalSign_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        bytes32 signerAccountDomainSeparator = signerAccount.domainSeparator();
        bytes32 wrappedPersonalSignDigest =
            TypedDataSignBuilder.hashWrappedPersonalSign(messageHash, signerAccountDomainSeparator);

        bytes memory signature = p256Key.sign(wrappedPersonalSignDigest);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);
        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(messageHash, wrappedSignature);
        vm.snapshotGasLastCall("isValidSignature_P256_personalSign");
        assertEq(result, _1271_MAGIC_VALUE);
    }

    /**
     * Scenario: Root key
     * 1. Not typed data sign
     * 2. Not nested personal sign
     * 3. Safe ERC1271 caller
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_rootKey_notTypedDataSign_safeERC1271Caller_isValid_gas() public {
        // Set the caller as safe
        vm.prank(address(signerAccount));
        signerAccount.setERC1271CallerIsSafe(address(mockERC1271VerifyingContract), true);

        (,, bytes32 contentsHash) = getERC1271Fixtures();
        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        // This is normally an unsafe digest to sign and would result in invalid signature
        // but we set the caller as safe so expect it to be valid
        bytes memory signature = signerTestKey.sign(digest);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);

        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
        vm.snapshotGasLastCall("isValidSignature_rootKey_typedData_notTypedDataSign_safeERC1271Caller");
    }

    /**
     * Scenario: P256 key
     * 1. Not typed data sign
     * 2. Not nested personal sign
     * 3. Safe ERC1271 caller
     * = valid signature
     */
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_isValidSignature_p256Key_notTypedDataSign_safeERC1271Caller_isValid_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.setERC1271CallerIsSafe(address(mockERC1271VerifyingContract), true);
        vm.stopPrank();

        (,, bytes32 contentsHash) = getERC1271Fixtures();
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        // This is normally an unsafe digest to sign and would result in invalid signature
        // but we set the caller as safe so expect it to be valid
        bytes memory signature = p256Key.sign(digest);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature, EMPTY_HOOK_DATA);

        vm.prank(address(mockERC1271VerifyingContract));
        bytes4 result = signerAccount.isValidSignature(digest, wrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
        vm.snapshotGasLastCall("isValidSignature_P256_typedData_notTypedDataSign_safeERC1271Caller");
    }

    /**
     *
     * MARK: Expired key tests
     *
     */
    function test_isValidSignature_sep256k1_typedDataSign_expiredKey_reverts() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, 0xb0b);
        bytes memory signature = key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(key.toKey());
        signerAccount.update(key.toKeyHash(), keySettings);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        vm.prank(address(mockERC1271VerifyingContract));
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_P256_typedDataSign_expiredKey_reverts() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes memory signature = p256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.warp(100);
        Settings keySettings = SettingsBuilder.init().fromExpiration(uint40(block.timestamp - 1));

        vm.startPrank(address(signerAccount));
        signerAccount.register(p256Key.toKey());
        signerAccount.update(p256Key.toKeyHash(), keySettings);
        vm.stopPrank();

        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.expectRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector, uint40(block.timestamp - 1)));
        vm.prank(address(mockERC1271VerifyingContract));
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    /**
     *
     * MARK: Invalid signer tests
     *
     */

    /**
     * Scenario: Root key
     * 1. Not typed data sign
     * 2. Not nested personal sign
     * 3. Not safe ERC1271 caller
     * = invalid signer
     */
    function test_isValidSignature_rootKey_notTypedDataSign_invalidSigner() public {
        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        // This is unsafe to sign because `digest` is not nested within a TypedDataSign
        bytes memory signature = signerTestKey.sign(digest);
        // Still build the signature as expected to pass in memory abi decoding
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);

        // ensure the call returns the ERC1271 invalid magic value
        vm.prank(address(mockERC1271VerifyingContract));
        assertEq(signerAccount.isValidSignature(digest, wrappedSignature), _1271_INVALID_VALUE);
    }

    /**
     * Scenario: Root key
     * 1. Not typed data sign
     * 2. Not nested personal sign
     * 3. Not safe ERC1271 caller
     * = invalid signer
     */
    function test_isValidSignature_rootKey_notNestedPersonalSign_isInvalid() public {
        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        // Incorrectly do personal_sign instead of over the typed PersonalSign digest
        bytes memory signature = signerTestKey.sign(messageHash);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature, EMPTY_HOOK_DATA);
        // Should return the invalid value
        assertEq(signerAccount.isValidSignature(messageHash, wrappedSignature), _1271_INVALID_VALUE);
    }

    // There is enough data to validate the signature using the TypedDataSign flow, so we expect to try that and for it to return false
    // then, we expect to use the NestedPersonalSign flow, which will cause an in memory decoding revert because it will try to decode
    // the wrapped typedDataSign signature as a WebAuthn.WebAuthnAuth struct
    function test_isValidSignature_WebAuthnP256_notTypedDataSign_reverts() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);
        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        // This is unsafe to sign because `digest` is not nested within a TypedDataSign
        bytes memory signature = webAuthnP256Key.sign(digest);
        // Still build the signature as expected to pass in memory abi decoding
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(webAuthnP256Key.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.expectRevert();
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    /**
     *
     * MARK: Other revert tests
     *
     */
    function test_isValidSignature_validSep256k1_reverts_keyDoesNotExist() public {
        // sign with an unregistered private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory wrappedSignature = abi.encode(invalidSigner.toKeyHash(), typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        vm.expectRevert(IKeyManagement.KeyDoesNotExist.selector);
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    /**
     *
     * MARK: Invalid wrapped signature construction tests
     *
     */
    function test_isValidSignature_WebAuthnP256_invalidWrappedSignatureLength_reverts() public {
        TestKey memory webAuthnP256Key = TestKeyManager.initDefault(KeyType.WebAuthnP256);

        bytes memory signature = webAuthnP256Key.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        // Intentionally don't wrap the signature with the key hash.
        bytes memory wrappedSignature = abi.encode(typedDataSignSignature, EMPTY_HOOK_DATA);

        vm.prank(address(signer));
        signerAccount.register(webAuthnP256Key.toKey());

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        vm.expectRevert();
        signerAccount.isValidSignature(digest, wrappedSignature);
    }

    function test_isValidSignature_sep256k1_typedDataSign_wrongKeyHash_invalidSigner() public {
        // sign with a different private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        TestKey memory invalidSigner = TestKeyManager.withSeed(KeyType.Secp256k1, invalidPrivateKey);
        bytes memory signature = invalidSigner.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        // trying to spoof the root key hash causes the signature verification to fail
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);

        // Built by the ERC1271 contract which hashes its domain separator to the contents hash
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));
        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(digest, wrappedSignature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_newDomainSeparatorInvalidatesOldSignatures() public {
        bytes memory signature = signerTestKey.sign(TEST_TYPED_DATA_SIGN_DIGEST);
        (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash) = getERC1271Fixtures();
        bytes memory typedDataSignSignature =
            TypedDataSignBuilder.buildTypedDataSignSignature(signature, appDomainSeparator, contentsHash, contentsDescr);
        bytes memory oldWrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, typedDataSignSignature, EMPTY_HOOK_DATA);
        // ensure the call returns the ERC1271 magic value
        bytes32 digest = mockERC1271VerifyingContract.hashTypedDataV4(contentsHash);
        vm.prank(address(mockERC1271VerifyingContract));

        // Make sure it is a valid signature before the domain separator is updated
        bytes4 result = signerAccount.isValidSignature(digest, oldWrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);

        // Update the salt, which changes the domain separator
        vm.prank(address(signerAccount));
        signerAccount.setSalt(keccak256(abi.encodePacked("new salt")));

        // Expect the old signature to be invalidated
        result = signerAccount.isValidSignature(digest, oldWrappedSignature);
        assertEq(result, _1271_INVALID_VALUE);

        // Build the new typed data sign digest
        // Everything stays the same besides the signer account's domainBytes
        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        bytes32 newTypedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appDomainSeparator, contentsName, contentsType);

        // Build the new wrapped signature
        bytes memory newSignature = signerTestKey.sign(newTypedDataSignDigest);
        bytes memory newTypedDataSignSignature = TypedDataSignBuilder.buildTypedDataSignSignature(
            newSignature, appDomainSeparator, contentsHash, contentsDescr
        );

        // Ensure we can sign with the new domain separator
        bytes memory newWrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, newTypedDataSignSignature, EMPTY_HOOK_DATA);
        result = signerAccount.isValidSignature(digest, newWrappedSignature);
        assertEq(result, _1271_MAGIC_VALUE);
    }
}

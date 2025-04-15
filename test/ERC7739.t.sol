// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {PermitSingle, PermitDetails, MockERC1271VerifyingContract} from "./utils/MockERC1271VerifyingContract.sol";
import {ERC1271Handler} from "./utils/ERC1271Handler.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {KeyType, Key, KeyLib} from "../src/libraries/KeyLib.sol";
import {TypedDataSignBuilder} from "./utils/TypedDataSignBuilder.sol";
import {FFISignTypedData} from "./utils/FFISignTypedData.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract ERC7739Test is DelegationHandler, TokenHandler, ERC1271Handler, FFISignTypedData {
    using TestKeyManager for TestKey;
    using TypedDataSignBuilder for *;
    using KeyLib for Key;

    function setUp() public {
        setUpDelegation();
        setUpTokens();
        setUpERC1271();
    }

    function test_signPersonalSign_matches_signWrappedPersonalSign_ffi() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);

        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        bytes32 signerAccountDomainSeparator = signerAccount.domainSeparator();
        bytes32 wrappedPersonalSignDigest = messageHash.hashWrappedPersonalSign(signerAccountDomainSeparator);

        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signWrappedPersonalSign(signerPrivateKey, verifyingContract, message);
        assertEq(signature, key.sign(wrappedPersonalSignDigest));
    }

    function test_signTypedSignData_matches_signWrappedTypedData_ffi() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);

        PermitSingle memory permitSingle = PermitSingle({
            details: PermitDetails({token: address(0), amount: 0, expiration: 0, nonce: 0}),
            spender: address(0),
            sigDeadline: 0
        });
        // Locally generate the full TypedSignData hash
        bytes32 contentsHash = mockERC1271VerifyingContract.hash(permitSingle);
        bytes32 appSeparator = mockERC1271VerifyingContract.domainSeparator();
        string memory contentsDescrExplicit = mockERC1271VerifyingContract.contentsDescrExplicit();

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsDescrExplicit);

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey,
            verifyingContract,
            DOMAIN_NAME,
            DOMAIN_VERSION,
            address(mockERC1271VerifyingContract),
            permitSingle
        );
        // Assert that the signature is valid when compared against the ffi generated signature
        assertEq(signature, key.sign(typedDataSignDigest));
    }

    function test_signTypedSignData_usingImplicitType_wrongSignature_ffi() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);

        PermitSingle memory permitSingle = PermitSingle({
            details: PermitDetails({token: address(0), amount: 0, expiration: 0, nonce: 0}),
            spender: address(0),
            sigDeadline: 0
        });
        // Locally generate the full TypedSignData hash
        bytes32 contentsHash = mockERC1271VerifyingContract.hash(permitSingle);
        bytes32 appSeparator = mockERC1271VerifyingContract.domainSeparator();

        // Incorrectly use the implicit type descriptor string, causing the top level type to be
        // TypeDataSign(...)PermitSingle(...)PermitDetails(...) which does not follow EIP-712 ordering
        string memory contentsDescrImplicit = mockERC1271VerifyingContract.contentsDescrImplicit();

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsDescrImplicit);

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey,
            verifyingContract,
            DOMAIN_NAME,
            DOMAIN_VERSION,
            address(mockERC1271VerifyingContract),
            permitSingle
        );
        // Assert that the ffi generated signature is NOT the same as the locally generated signature
        assertNotEq(signature, key.sign(typedDataSignDigest));
    }
}

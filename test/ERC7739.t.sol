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

contract ERC7739Test is DelegationHandler, TokenHandler, ERC1271Handler, FFISignTypedData {
    using TestKeyManager for TestKey;
    using TypedDataSignBuilder for bytes32;
    using TypedDataSignBuilder for IERC5267;
    using KeyLib for Key;

    function setUp() public {
        setUpDelegation();
        setUpTokens();
        setUpERC1271();
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
        string memory contentsDescr = mockERC1271VerifyingContract.contentsDescr();

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsDescr);

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey, 
            verifyingContract, 
            mockERC1271VerifyingContract.EIP712Name(), 
            mockERC1271VerifyingContract.EIP712Version(), 
            permitSingle
        );
        // Assert that the signature is valid when compared against the ffi generated signature
        assertEq(signature, key.sign(typedDataSignDigest));
    }
}

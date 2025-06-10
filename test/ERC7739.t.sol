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
import {Permit2Utils} from "./utils/Permit2Utils.sol";
import {IPermit2} from "../lib/permit2/src/interfaces/IPermit2.sol";
import {IAllowanceTransfer} from "../lib/permit2/src/interfaces/IAllowanceTransfer.sol";

contract ERC7739Test is DelegationHandler, TokenHandler, ERC1271Handler, FFISignTypedData {
    using TestKeyManager for TestKey;
    using TypedDataSignBuilder for *;
    using KeyLib for Key;
    using Permit2Utils for *;

    IAllowanceTransfer public permit2;

    function setUp() public {
        setUpDelegation();
        setUpTokens();
        // Deploy permit2 for actual permit transfers
        permit2 = IAllowanceTransfer(Permit2Utils.deployPermit2());
    }

    function test_signPersonalSign_matches_signWrappedPersonalSign_ffi() public {
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);

        string memory message = "test";
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(bytes(message));
        bytes32 signerAccountDomainSeparator = signerAccount.domainSeparator();
        bytes32 wrappedPersonalSignDigest = messageHash.hashWrappedPersonalSign(signerAccountDomainSeparator);

        address verifyingContract = address(signerAccount);
        (,,,,, bytes32 salt,) = signerAccount.eip712Domain();

        (bytes memory signature) = ffi_signWrappedPersonalSign(signerPrivateKey, verifyingContract, salt, message);
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
        (string memory contentsName, string memory contentsType) =
            mockERC7739Utils.decodeContentsDescr(contentsDescrExplicit);

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsName, contentsType);

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);
        (,,,,, bytes32 salt,) = signerAccount.eip712Domain();

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey,
            verifyingContract,
            salt,
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
        (string memory contentsName, string memory contentsType) =
            mockERC7739Utils.decodeContentsDescr(contentsDescrImplicit);

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsName, contentsType);

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);
        (,,,,, bytes32 salt,) = signerAccount.eip712Domain();

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey,
            verifyingContract,
            salt,
            DOMAIN_NAME,
            DOMAIN_VERSION,
            address(mockERC1271VerifyingContract),
            permitSingle
        );
        // Assert that the ffi generated signature is NOT the same as the locally generated signature
        assertNotEq(signature, key.sign(typedDataSignDigest));
    }

    function test_signTypedSignData_permitSingleTransfer_actualTransfer() public {
        // Create a test key with a different private key and register it with the signer account
        uint256 testPrivateKey = 0x123456;
        TestKey memory testKey = TestKeyManager.withSeed(KeyType.Secp256k1, testPrivateKey);
        vm.prank(address(signerAccount));
        signerAccount.register(testKey.toKey());

        // Set up real amounts and addresses for the permit transfer
        uint160 permitAmount = 1000 * 10**18; // 1000 tokens
        uint48 permitExpiration = uint48(block.timestamp + 3600); // 1 hour from now
        address spender = address(this); // This test contract will be the spender
        address recipient = makeAddr("recipient");

        // Mint tokens to the signer account
        tokenA.mint(address(signerAccount), permitAmount);
        
        // The signer account needs to approve permit2 to spend its tokens
        vm.prank(address(signerAccount));
        tokenA.approve(address(permit2), type(uint256).max);

        // Get the current nonce for the permit
        (,, uint48 currentNonce) = permit2.allowance(address(signerAccount), address(tokenA), spender);

        // Create the permit using the IAllowanceTransfer structs
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: address(tokenA), 
                amount: permitAmount, 
                expiration: permitExpiration, 
                nonce: currentNonce
            }),
            spender: spender,
            sigDeadline: uint256(block.timestamp + 3600)
        });

        // Now we need to create an ERC7739 signature for this permit
        // Use permit2's domain and the actual permit hash that permit2 will verify
        bytes32 permit2DomainSeparator = IPermit2(address(permit2)).DOMAIN_SEPARATOR();
        bytes32 permitHash = keccak256(abi.encode(
            keccak256("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"),
            keccak256(abi.encode(
                keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"),
                permitSingle.details.token,
                permitSingle.details.amount,
                permitSingle.details.expiration,
                permitSingle.details.nonce
            )),
            permitSingle.spender,
            permitSingle.sigDeadline
        ));

        // Create ERC7739 wrapped signature
        // The TypedDataSign structure wraps the permit hash (contents) within the signer account's domain
        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        bytes32 typedDataSignDigest = permitHash.hashTypedDataSign(
            signerAccountDomainBytes,
            permit2DomainSeparator,
            "PermitSingle",
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
        );

        // Sign with the registered test key
        bytes memory signature = testKey.sign(typedDataSignDigest);

        // Build the ERC7739 signature structure
        bytes memory erc7739Sig = TypedDataSignBuilder.buildTypedDataSignSignature(
            signature,
            permit2DomainSeparator,
            permitHash, // Use the permit hash, not the full EIP-712 digest
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)PermitSingle"
        );
        bytes memory wrappedSignature = abi.encode(testKey.toKeyHash(), erc7739Sig, "");

        // Record balances before transfer
        uint256 signerBalanceBefore = tokenA.balanceOf(address(signerAccount));
        uint256 recipientBalanceBefore = tokenA.balanceOf(recipient);

        // Execute the permit using the wrapped signature
        permit2.permit(address(signerAccount), permitSingle, wrappedSignature);

        // Verify permit was set correctly
        (uint160 allowanceAmount, uint48 allowanceExpiration,) = 
            permit2.allowance(address(signerAccount), address(tokenA), spender);
        assertEq(allowanceAmount, permitAmount);
        assertEq(allowanceExpiration, permitExpiration);

        // Transfer tokens using the permit
        uint160 transferAmount = 500 * 10**18; // Transfer half the permitted amount
        permit2.transferFrom(address(signerAccount), recipient, transferAmount, address(tokenA));

        // Verify the transfer worked
        assertEq(tokenA.balanceOf(address(signerAccount)), signerBalanceBefore - transferAmount);
        assertEq(tokenA.balanceOf(recipient), recipientBalanceBefore + transferAmount);

        // Verify the allowance was reduced
        (uint160 remainingAllowance,,) = 
            permit2.allowance(address(signerAccount), address(tokenA), spender);
        assertEq(remainingAllowance, permitAmount - transferAmount);
    }
}

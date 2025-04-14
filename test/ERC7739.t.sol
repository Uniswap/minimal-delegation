// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
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

    function test_domainSeparator() public view {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = signerAccount.eip712Domain();
        // Ensure that verifying contract is the signer
        assertEq(verifyingContract, address(signerAccount));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
        assertEq(salt, bytes32(0));
        assertEq(name, "Uniswap Minimal Delegation");
        assertEq(version, "1");
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, signerAccount.domainSeparator());

        console2.logBytes32(keccak256(bytes(name)));
        console2.logBytes32(keccak256(bytes(version)));
        console2.log(chainId);
        console2.log(verifyingContract);
        console2.logBytes32(salt);
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
        console2.log("test contentsHash");
        console2.logBytes32(contentsHash);
        bytes32 appSeparator = mockERC1271VerifyingContract.domainSeparator();
        console2.log("test appSeparator");
        console2.logBytes32(appSeparator);
        string memory contentsDescrExplicit = mockERC1271VerifyingContract.contentsDescrExplicit();
        console2.log("test contentsDescrExplicit %s", contentsDescrExplicit);

        bytes memory signerAccountDomainBytes = IERC5267(address(signerAccount)).toDomainBytes();
        console2.log("test signerAccountDomainBytes");
        console2.logBytes(signerAccountDomainBytes);
        bytes32 typedDataSignDigest =
            contentsHash.hashTypedDataSign(signerAccountDomainBytes, appSeparator, contentsDescrExplicit);

        console2.log("test typedDataSignDigest");
        console2.logBytes32(typedDataSignDigest);

        

        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signWrappedTypedData(
            signerPrivateKey, 
            verifyingContract, 
            mockERC1271VerifyingContract.EIP712Name(), 
            mockERC1271VerifyingContract.EIP712Version(), 
            address(mockERC1271VerifyingContract),
            permitSingle
        );
        // Assert that the signature is valid when compared against the ffi generated signature
        assertEq(signature, key.sign(typedDataSignDigest));
    }
}

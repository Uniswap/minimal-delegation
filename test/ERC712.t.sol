// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC5267} from "openzeppelin-contracts/contracts/interfaces/IERC5267.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC1271} from "../src/interfaces/IERC1271.sol";
import {IEIP712} from "../src/interfaces/IEIP712.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {HandlerCall, CallUtils} from "./utils/CallUtils.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {CallLib} from "../src/libraries/CallLib.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {FFISignTypedData} from "./utils/FFISignTypedData.sol";
import {SignedBatchedCallLib, SignedBatchedCall} from "../src/libraries/SignedBatchedCallLib.sol";
import {BatchedCallLib, BatchedCall} from "../src/libraries/BatchedCallLib.sol";

contract ERC712Test is DelegationHandler, TokenHandler, FFISignTypedData {
    using WrappedDataHash for bytes32;
    using CallLib for Call[];
    using CallUtils for *;
    using TestKeyManager for TestKey;
    using SignedBatchedCallLib for SignedBatchedCall;
    using BatchedCallLib for BatchedCall;

    address receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpTokens();
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
    }

    /// TODO: We can replace this with ffi test to be more resilient to solidity implementation changes.
    function test_hashTypedData() public view {
        SignedBatchedCall memory signedBatchedCall = CallUtils.initSignedBatchedCall();
        bytes32 hashTypedData = signerAccount.hashTypedData(signedBatchedCall.hash());
        // re-implement 712 hash
        bytes32 expected =
            keccak256(abi.encodePacked("\x19\x01", signerAccount.domainSeparator(), signedBatchedCall.hash()));
        assertEq(expected, hashTypedData);
    }

    function test_hashTypedData_matches_signedTypedData_ffi() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        uint256 nonce = 0;
        BatchedCall memory batchedCall = CallUtils.initBatchedCall().withCalls(calls).withShouldRevert(true);
        SignedBatchedCall memory signedBatchedCall =
            CallUtils.initSignedBatchedCall().withBatchedCall(batchedCall).withNonce(nonce);
        TestKey memory key = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);
        // Make it clear that the verifying contract is set properly.
        address verifyingContract = address(signerAccount);

        (bytes memory signature) = ffi_signTypedData(signerPrivateKey, signedBatchedCall, verifyingContract);

        assertEq(signature, key.sign(signerAccount.hashTypedData(signedBatchedCall.hash())));
    }
}

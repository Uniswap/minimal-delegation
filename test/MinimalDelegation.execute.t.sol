// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {ExecuteHandler} from "./utils/ExecuteHandler.sol";
import {HookHandler} from "./utils/HookHandler.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {CallLib} from "../src/libraries/CallLib.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {HandlerCall, CallUtils} from "./utils/CallUtils.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20Errors} from "openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";
import {EIP712} from "../src/EIP712.sol";
import {CallLib} from "../src/libraries/CallLib.sol";
import {NonceManager} from "../src/NonceManager.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {KeyType, KeyLib, Key} from "../src/libraries/KeyLib.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {SignedCallsLib, SignedCalls} from "../src/libraries/SignedCallsLib.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";

contract MinimalDelegationExecuteTest is TokenHandler, HookHandler, ExecuteHandler, DelegationHandler {
    using TestKeyManager for TestKey;
    using KeyLib for Key;
    using CallUtils for Call[];
    using CallLib for Call[];
    using SignedCallsLib for SignedCalls;
    using SettingsLib for Settings;
    using SettingsBuilder for Settings;

    address receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpTokens();
        setUpHooks();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);
    }

    /// Helper function to get the next available nonce
    function _buildNextValidNonce(uint256 key) internal view returns (uint256 nonce, uint64 seq) {
        seq = uint64(signerAccount.getSeq(key));
        nonce = key << 64 | seq;
    }

    function test_execute_reverts_withUnsupportedExecutionMode() public {
        // Test specific modes since the fuzz is just over the first 2 bytes.
        bytes32[] memory modes = new bytes32[](3);
        bytes32 invalid_mode_1 = 0x0101100000000000000000000000000000000000000000000000000000000000;
        bytes32 invalid_mode_2 = 0x0100000000000a00000000000000000000000000000000000000000000000000;
        bytes32 invalid_mode_3 = 0x010100000000000000000000000000000000000000000000000000000000000a;
        modes[0] = invalid_mode_1;
        modes[1] = invalid_mode_2;
        modes[2] = invalid_mode_3;

        vm.startPrank(address(signerAccount));
        for (uint256 i = 0; i < modes.length; i++) {
            bytes32 mode = modes[i];
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
            signerAccount.execute(mode, abi.encode(CallUtils.initArray()));
        }
        vm.stopPrank();
    }

    function test_execute_fuzz_reverts(uint16 _mode) public {
        uint256 zeros = uint256(0);
        bytes32 mode = bytes32(uint256(_mode) << 240 | zeros);
        vm.prank(address(signerAccount));
        if (mode != BATCHED_CALL && mode != BATCHED_CAN_REVERT_CALL) {
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
        }
        signerAccount.execute(mode, abi.encode(CallUtils.initArray()));
    }

    function test_execute_auth_reverts() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.execute(BATCHED_CALL, abi.encode(CallUtils.initArray()));
    }

    function test_execute() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        assertEq(tokenA.balanceOf(address(signerAccount)), 100e18);
        assertEq(tokenB.balanceOf(address(signerAccount)), 100e18);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);

        uint256 nativeBalanceBefore = address(signerAccount).balance;
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(tokenB.balanceOf(address(receiver)), 1e18);
        // native balance should not change
        assertEq(address(signerAccount).balance, nativeBalanceBefore);
    }

    function test_execute_native() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(address(receiver).balance, 1e18);
    }

    function test_execute_batch_reverts() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call should cause the entire batch to revert
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        bytes memory balanceError = abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientBalance.selector, address(signerAccount), 100e18, 101e18
        );
        vm.expectRevert(abi.encodeWithSelector(IERC7821.CallFailed.selector, balanceError));
        signerAccount.execute(BATCHED_CALL, executionData);
    }

    function test_execute_batch_canRevert_succeeds() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call reverts but the batch should succeed
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CAN_REVERT_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        // the second transfer failed
        assertEq(tokenB.balanceOf(address(receiver)), 0);
    }

    // Execute can contain a self call which registers a new key even if the caller is untrusted as long as the signature is valid
    function test_execute_opData_eoaSigner_selfCall_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        Call[] memory calls = CallUtils.initArray();
        Call memory registerCall =
            Call(address(0), 0, abi.encodeWithSelector(IKeyManagement.register.selector, p256Key.toKey()));
        calls = calls.push(registerCall);

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});

        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);

        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature);
        bytes memory opData = abi.encode(nonce, wrappedSignature);
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(signerAccount.getKey(p256Key.toKeyHash()).hash(), p256Key.toKeyHash());
    }

    function test_execute_opData_P256_selfCall_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        TestKey memory secp256k1Key = TestKeyManager.initDefault(KeyType.Secp256k1);

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        Call[] memory calls = CallUtils.initArray();
        Call memory registerCall =
            Call(address(0), 0, abi.encodeWithSelector(IKeyManagement.register.selector, secp256k1Key.toKey()));
        calls = calls.push(registerCall);

        // Sign using the registered P256 key
        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(DEFAULT_NONCE).hash());
        bytes memory wrappedSignature = _signAndPack(digest, p256Key);
        bytes memory opData = abi.encode(DEFAULT_NONCE, wrappedSignature);
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(signerAccount.getKey(secp256k1Key.toKeyHash()).hash(), secp256k1Key.toKeyHash());
    }

    // Root EOA using key.hash() will revert with KeyDoesNotExist
    function test_execute_batch_opData_rootEOA_withKeyHash_reverts() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA

        uint256 nonceKey = 0;
        (uint256 nonce, uint64 seq) = _buildNextValidNonce(nonceKey);

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());

        bytes memory signature = signerTestKey.sign(hashToSign);

        // Pack the execution data:
        // 1. Encode the nonce and signature into opData
        bytes memory opData = abi.encode(nonce, abi.encode(KeyLib.ROOT_KEY_HASH, signature));
        // 2. Encode the calls and opData together
        bytes memory executionData = abi.encode(calls, opData);

        // Execute the batch of calls with the signature
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        // Verify the transfers succeeded
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(tokenB.balanceOf(address(receiver)), 1e18);

        // Verify the nonce was incremented - sequence should increase by 1
        assertEq(signerAccount.getSeq(nonceKey), seq + 1);
    }

    // Root EOA must use bytes32(0) as their keyHash
    function test_execute_batch_opData_rootEOA_withKeyHashZero_succeeds() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(nonce).hash());
        // Since root signer is signing, don't need to wrap the signature
        bytes memory opData = abi.encode(nonce, signerTestKey.sign(digest));
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
    }

    function test_execute_batch_opData_rootEOA_singleCall_succeeds() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA

        uint256 nonceKey = 0;
        (uint256 nonce, uint64 seq) = _buildNextValidNonce(nonceKey);

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);

        // Pack the execution data:
        // 1. Encode the nonce and signature into opData
        bytes memory opData = abi.encode(nonce, abi.encode(KeyLib.ROOT_KEY_HASH, signature));
        // 2. Encode the calls and opData together
        bytes memory executionData = abi.encode(calls, opData);

        // Execute the batch of calls with the signature
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        // Verify the transfers succeeded
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        // Verify the nonce was incremented - sequence should increase by 1
        assertEq(signerAccount.getSeq(nonceKey), seq + 1);
    }

    function test_execute_batch_opData_withHook_verifySignature_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        // Signature over a wrong digest
        bytes memory signature = p256Key.sign(KeyLib.ROOT_KEY_HASH);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature);
        bytes memory executionData = abi.encode(calls, abi.encode(nonce, wrappedSignature));

        // Expect the signature to be invalid (because it is)
        vm.expectRevert(IERC7821.InvalidSignature.selector);
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        // Expect the signature to be valid after adding the hook
        vm.prank(address(signerAccount));
        Settings keySettings = SettingsBuilder.init().fromHook(mockHook);
        signerAccount.update(p256Key.toKeyHash(), keySettings);
        mockHook.setVerifySignatureReturnValue(true);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
    }

    function test_execute_batch_opData_withHook_beforeExecute() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        uint192 key = 0;
        uint64 seq = uint64(signerAccount.getSeq(key));
        uint256 nonce = key << 64 | seq;

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = p256Key.sign(hashToSign);

        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), signature);
        bytes memory executionData = abi.encode(calls, abi.encode(nonce, wrappedSignature));

        bytes memory revertData = bytes("revert");
        mockExecutionHook.setBeforeExecuteRevertData(revertData);
        Settings keySettings = SettingsBuilder.init().fromHook(mockExecutionHook);

        vm.prank(address(signerAccount));
        signerAccount.update(p256Key.toKeyHash(), keySettings);

        // Expect the call to revert
        vm.expectRevert("revert");
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        // Unset the hook revert
        mockExecutionHook.setBeforeExecuteRevertData(bytes(""));

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
    }

    function test_execute_batch_opData_revertsWithInvalidNonce() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18)); // Transfer 1 tokenB

        // Get the current nonce components for key 0
        uint256 nonceKey = 0;
        (uint256 nonce, uint64 seq) = _buildNextValidNonce(nonceKey);

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, hashToSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Pack the execution data:
        // 1. Encode the nonce and signature into opData
        bytes memory opData = abi.encode(nonce, abi.encode(KeyLib.ROOT_KEY_HASH, signature));
        // 2. Encode the calls and opData together
        bytes memory executionData = abi.encode(calls, opData);

        // Execute the batch of calls with the signature
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        // Verify the nonce was incremented - sequence should increase by 1
        assertEq(signerAccount.getSeq(nonceKey), seq + 1);

        // Try to execute again with same nonce - should revert
        vm.expectRevert(INonceManager.InvalidNonce.selector);
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
    }

    /// GAS TESTS
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_reverts_withUnsupportedExecutionMode_gas() public {
        bytes32 invalid_mode = 0x0101100000000000000000000000000000000000000000000000000000000000;
        vm.prank(address(signerAccount));
        try signerAccount.execute(invalid_mode, abi.encode(CallUtils.initArray())) {}
        catch {
            vm.snapshotGasLastCall("execute_invalidMode_reverts");
        }
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_twoCalls_batchedCall_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        assertEq(tokenA.balanceOf(address(signerAccount)), 100e18);
        assertEq(tokenB.balanceOf(address(signerAccount)), 100e18);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_twoCalls");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_native_single_batchedCall_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_singleCall_native");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_opData_rootSigner_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature);
        bytes memory opData = abi.encode(nonce, wrappedSignature);

        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_opData_P256_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(DEFAULT_NONCE).hash());
        bytes memory wrappedSignature = _signAndPack(digest, p256Key);
        bytes memory opData = abi.encode(DEFAULT_NONCE, wrappedSignature);
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_P256_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_twoCalls_batchedCall_opData_rootSigner_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);
        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature);
        bytes memory opData = abi.encode(nonce, wrappedSignature);

        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_twoCalls");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_native_single_batchedCall_opData_eoaSigner_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);

        bytes memory wrappedSignature = abi.encode(KeyLib.ROOT_KEY_HASH, signature);

        bytes memory executionData = abi.encode(calls, abi.encode(nonce, wrappedSignature));

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_singleCall_native");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_batch_opData_singeCall_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA

        // Get the current nonce components for key 0
        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());
        bytes memory signature = signerTestKey.sign(hashToSign);

        // Pack the execution data:
        // 1. Encode the nonce and signature into opData
        bytes memory opData = abi.encode(nonce, abi.encode(KeyLib.ROOT_KEY_HASH, signature));
        // 2. Encode the calls and opData together
        bytes memory executionData = abi.encode(calls, opData);

        // Execute the batch of calls with the signature
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_SUPPORTS_OPDATA_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_batch_opData_twoCalls_gas() public {
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18)); // Transfer 1 tokenA
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18)); // Transfer 1 tokenB

        // Get the current nonce components for key 0
        uint256 nonceKey = 0;
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        // Create hash of the calls + nonce and sign it
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        bytes32 hashToSign = signerAccount.hashTypedData(signedCalls.hash());

        bytes memory signature = signerTestKey.sign(hashToSign);

        // Pack the execution data:
        // 1. Encode the nonce and signature into opData
        bytes memory opData = abi.encode(nonce, abi.encode(KeyLib.ROOT_KEY_HASH, signature));
        // 2. Encode the calls and opData together
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_SUPPORTS_OPDATA_twoCalls");
    }

    /**
     * Edge case tests
     */
    function test_execute_batch_emptyCalls_succeeds() public {
        Call[] memory calls = CallUtils.initArray();
        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, abi.encode(calls));
    }

    function test_execute_batch_emptyCalls_revertsWhenUnauthorized() public {
        Call[] memory calls = CallUtils.initArray();
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.execute(BATCHED_CALL, abi.encode(calls));
    }

    /**
     * Self call tests
     */
    function test_execute_register_update_asRoot_succeeds() public {
        TestKey memory newKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(CallUtils.encodeRegisterCall(newKey));
        calls = calls.push(CallUtils.encodeUpdateCall(newKey.toKeyHash(), Settings.wrap(0)));

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, abi.encode(calls));
    }

    function test_execute_register_update_asNonRoot_reverts() public {
        TestKey memory newKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(CallUtils.encodeRegisterCall(newKey));
        calls = calls.push(CallUtils.encodeUpdateCall(newKey.toKeyHash(), Settings.wrap(0)));

        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.execute(BATCHED_CALL, abi.encode(calls));
    }

    function test_execute_register_update_withRootSignature_succeeds() public {
        // Generate a test key to register
        TestKey memory newKey = TestKeyManager.initDefault(KeyType.Secp256k1);
        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(CallUtils.encodeRegisterCall(newKey));
        calls = calls.push(CallUtils.encodeUpdateCall(newKey.toKeyHash(), Settings.wrap(0)));

        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(DEFAULT_NONCE).hash());
        // Since root signer is signing, don't need to wrap the signature
        bytes memory opData = abi.encode(DEFAULT_NONCE, signerTestKey.sign(digest));
        bytes memory executionData = abi.encode(calls, opData);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        assertEq(Settings.unwrap(signerAccount.getKeySettings(newKey.toKeyHash())), 0);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {TokenHandler} from "./utils/TokenHandler.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {ExecuteHandler} from "./utils/ExecuteHandler.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC4337Account} from "../src/ERC4337Account.sol";
import {UserOpBuilder} from "./utils/UserOpBuilder.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract MinimalDelegation4337Test is DelegationHandler, TokenHandler, ExecuteHandler {
    using CallBuilder for Call[];
    using UserOpBuilder for PackedUserOperation;
    using TestKeyManager for TestKey;

    address receiver = makeAddr("receiver");
    address payable bundler = payable(makeAddr("bundler"));

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_handleOps_single_eoaSigner_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        /// This is extremely jank, but we have to encode the calls with the executeUserOp selector so the 4337 entrypoint forces a call to executeUserOp on the account.
        bytes memory executionData = abi.encode(calls);
        bytes memory callData =
            abi.encodeWithSelector(IAccountExecute.executeUserOp.selector, BATCHED_CALL, executionData);

        PackedUserOperation memory userOp =
            UserOpBuilder.initDefault().withSender(address(signerAccount)).withNonce(0).withCallData(callData);

        bytes32 digest = entryPoint.getUserOpHash(userOp);
        userOp.withSignature(signerTestKey.sign(digest));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        uint256 tokenBalanceBefore = tokenA.balanceOf(address(receiver));

        entryPoint.handleOps(userOps, bundler);
        vm.snapshotGasLastCall("hanldeOps_BATCHED_CALL_singleCall_eoaSigner");

        uint256 tokenBalanceAfter = tokenA.balanceOf(address(receiver));
        assertEq(tokenBalanceAfter, tokenBalanceBefore + 1e18);
    }

    function test_handleOps_single_eoaSigner_emits_UserOperationRevertReason() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);
        bytes memory callData =
            abi.encodeWithSelector(IAccountExecute.executeUserOp.selector, BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        PackedUserOperation memory userOp =
            UserOpBuilder.initDefault().withSender(address(signerAccount)).withNonce(0).withCallData(callData);

        bytes32 digest = entryPoint.getUserOpHash(userOp);
        userOp.withSignature(signerTestKey.sign(digest));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectEmit(true, true, true, true);
        emit IEntryPoint.UserOperationRevertReason(
            entryPoint.getUserOpHash(userOp),
            address(signerAccount),
            0,
            abi.encodeWithSelector(IERC7821.UnsupportedExecutionMode.selector)
        );
        entryPoint.handleOps(userOps, bundler);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_handleOps_single_P256_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        signerAccount.register(p256Key.toKey());

        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        bytes memory opData = bytes("");
        bytes memory executionData = abi.encode(calls, opData);
        bytes memory callData =
            abi.encodeWithSelector(IAccountExecute.executeUserOp.selector, BATCHED_CALL, executionData);

        PackedUserOperation memory userOp =
            UserOpBuilder.initDefault().withSender(address(signerAccount)).withNonce(0).withCallData(callData);

        bytes32 digest = entryPoint.getUserOpHash(userOp);
        bytes memory wrappedSignature = abi.encode(p256Key.toKeyHash(), p256Key.sign(digest));
        userOp.withSignature(wrappedSignature);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        uint256 tokenBalanceBefore = tokenA.balanceOf(address(receiver));

        entryPoint.handleOps(userOps, bundler);
        vm.snapshotGasLastCall("hanldeOps_BATCHED_CALL_singleCall_P256");

        uint256 tokenBalanceAfter = tokenA.balanceOf(address(receiver));
        assertEq(tokenBalanceAfter, tokenBalanceBefore + 1e18);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
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

        vm.prank(address(signerAccount));
        signerAccount.updateEntryPoint(address(entryPoint));
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_handleOps_single_eoaSigner_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        // TODO: encode nonce into opData
        bytes memory opData = bytes("");
        bytes memory executionData = abi.encode(calls, opData);
        bytes memory callData =
            abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL_SUPPORTS_OPDATA, executionData);

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

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_handleOps_single_P256_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);
        bytes32 keyHash = p256Key.toKeyHash();

        vm.startPrank(address(signerAccount));
        signerAccount.authorize(p256Key.toKey());
        /// The key CANNOT execute the transfer
        signerAccount.setCanExecute(keyHash, address(tokenA), ERC20.transfer.selector, false);
        vm.stopPrank();

        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        /// Pass keyHash in opData
        /// This can be spoofed! Set it to 0 to bypass the permissions check set above
        bytes memory opData = abi.encode(bytes32(0));
        bytes memory executionData = abi.encode(calls, opData);
        bytes memory callData =
            abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL_SUPPORTS_OPDATA, executionData);

        PackedUserOperation memory userOp =
            UserOpBuilder.initDefault().withSender(address(signerAccount)).withNonce(0).withCallData(callData);

        bytes32 digest = entryPoint.getUserOpHash(userOp);
        /// Add the keyHash to the signature for verification within validateUserOp
        bytes memory wrappedSignature = abi.encode(keyHash, p256Key.sign(digest));
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

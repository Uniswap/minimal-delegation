// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {CallLib} from "../src/libraries/CallLib.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IERC20Errors} from "openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {ExecutionDataLib, ExecutionData} from "../src/libraries/ExecuteLib.sol";

contract MinimalDelegationExecuteTest is TokenHandler, DelegationHandler {
    using TestKeyManager for TestKey;
    using CallBuilder for Call[];
    using CallLib for Call[];
    using ExecutionDataLib for ExecutionData;

    bytes32 constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CAN_REVERT_CALL = 0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CALL_SUPPORTS_OPDATA = 0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;

    address receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);
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
            signerAccount.execute(mode, abi.encode(CallBuilder.init()));
        }
    }

    function test_execute_fuzz_reverts(uint16 _mode) public {
        uint256 zeros = uint256(0);
        bytes32 mode = bytes32(uint256(_mode) << 240 | zeros);
        vm.startPrank(address(signerAccount));
        if (mode != BATCHED_CALL && mode != BATCHED_CAN_REVERT_CALL) {
            vm.expectRevert(IERC7821.UnsupportedExecutionMode.selector);
        }
        signerAccount.execute(mode, abi.encode(CallBuilder.init()));
    }

    function test_execute_auth_reverts() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.execute(BATCHED_CALL, abi.encode(CallBuilder.init()));
    }

    function test_execute() public {
        Call[] memory calls = CallBuilder.init();
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
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        assertEq(address(receiver).balance, 1e18);
    }

    function test_execute_batch_reverts() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call should cause the entire batch to revert
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.startPrank(address(signerAccount));
        bytes memory balanceError = abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientBalance.selector, address(signerAccount), 100e18, 101e18
        );
        vm.expectRevert(abi.encodeWithSelector(IERC7821.CallFailed.selector, balanceError));
        signerAccount.execute(BATCHED_CALL, executionData);
    }

    function test_execute_batch_canRevert_succeeds() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        // this call reverts but the batch should succeed
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 101e18));

        bytes memory executionData = abi.encode(calls);

        vm.startPrank(address(signerAccount));
        signerAccount.execute(BATCHED_CAN_REVERT_CALL, executionData);

        assertEq(tokenA.balanceOf(address(receiver)), 1e18);
        // the second transfer failed
        assertEq(tokenB.balanceOf(address(receiver)), 0);
    }

    /// GAS TESTS
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_reverts_withUnsupportedExecutionMode_gas() public {
        bytes32 invalid_mode = 0x0101100000000000000000000000000000000000000000000000000000000000;
        vm.startPrank(address(signerAccount));
        try signerAccount.execute(invalid_mode, abi.encode(CallBuilder.init())) {}
        catch {
            vm.snapshotGasLastCall("execute_invalidMode_reverts");
        }
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_twoCalls_batchedCall_gas() public {
        Call[] memory calls = CallBuilder.init();
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
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));

        bytes memory executionData = abi.encode(calls);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_singleCall_native");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_opData_eoaSigner_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        ExecutionData memory execute = ExecutionData({calls: calls});
        // TODO: remove 0 nonce
        bytes memory signature = abi.encode(0, signerTestKey.sign(signerAccount.hashTypedData(execute.hash())));

        bytes memory executionData = abi.encode(calls, signature);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_single_batchedCall_opData_P256_gas() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        ExecutionData memory execute = ExecutionData({calls: calls});

        vm.startPrank(address(signer));
        signerAccount.authorize(p256Key.toKey());

        // TODO: remove 0 nonce
        bytes memory packedSignature =
            abi.encode(0, abi.encode(p256Key.toKeyHash(), p256Key.sign(signerAccount.hashTypedData(execute.hash()))));

        bytes memory executionData = abi.encode(calls, packedSignature);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_P256_singleCall");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_twoCalls_batchedCall_opData_eoaSigner_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));
        calls = calls.push(buildTransferCall(address(tokenB), address(receiver), 1e18));
        ExecutionData memory execute = ExecutionData({calls: calls});
        // sign via EOA
        // TODO: remove 0 nonce
        bytes memory signature = abi.encode(0, signerTestKey.sign(signerAccount.hashTypedData(execute.hash())));

        bytes memory executionData = abi.encode(calls, signature);

        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_twoCalls");
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_execute_native_single_batchedCall_opData_eoaSigner_gas() public {
        Call[] memory calls = CallBuilder.init();
        calls = calls.push(buildTransferCall(address(0), address(receiver), 1e18));
        ExecutionData memory execute = ExecutionData({calls: calls});

        // TODO: remove 0 nonce
        bytes memory signature = abi.encode(0, signerTestKey.sign(signerAccount.hashTypedData(execute.hash())));

        bytes memory executionData = abi.encode(calls, signature);

        vm.prank(address(signerAccount));
        signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData);
        vm.snapshotGasLastCall("execute_BATCHED_CALL_opData_singleCall_native");
    }
}

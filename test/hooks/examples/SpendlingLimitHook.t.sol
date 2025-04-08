// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {SpendPeriod, ISpendingLimitHook, SpendingLimitHook} from "../../../src/hooks/execution/SpendingLimitHook.sol";
import {DelegationHandler} from "../../utils/DelegationHandler.sol";
import {HookHandler} from "../../utils/HookHandler.sol";
import {TokenHandler} from "../../utils/TokenHandler.sol";
import {TestKey, TestKeyManager} from "../../utils/TestKeyManager.sol";
import {Key, KeyType, KeyLib} from "../../../src/libraries/KeyLib.sol";
import {IHook} from "../../../src/interfaces/IHook.sol";
import {IExecutionHook} from "../../../src/interfaces/IExecutionHook.sol";
import {AccountKeyHash, AccountKeyHashLib} from "../../../src/hooks/shared/AccountKeyHashLib.sol";
import {Call} from "../../../src/libraries/CallLib.sol";

contract SpendlingLimitHookTest is HookHandler, DelegationHandler, TokenHandler {
    using TestKeyManager for TestKey;
    using AccountKeyHashLib for bytes32;

    SpendingLimitHook internal spendingLimitHook;
    address internal receiver = makeAddr("receiver");

    function setUp() public {
        setUpDelegation();
        setUpHooks();
        setUpTokens();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);

        spendingLimitHook = new SpendingLimitHook();
    }

    function test_setSpendLimit_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        AccountKeyHash accountKeyHash = p256Key.toKeyHash().wrap(address(signerAccount));
        // check that the spend limit is set
        vm.expectEmit(true, true, true, true);
        emit ISpendingLimitHook.SpendLimitSet(accountKeyHash, address(tokenA), SpendPeriod.Minute, 100);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), SpendPeriod.Minute, 100);
    }

    function test_setSpendLimit_native_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        AccountKeyHash accountKeyHash = p256Key.toKeyHash().wrap(address(signerAccount));
        // check that the spend limit is set
        vm.expectEmit(true, true, true, true);
        emit ISpendingLimitHook.SpendLimitSet(accountKeyHash, address(0), SpendPeriod.Minute, 100);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(0), SpendPeriod.Minute, 100);
    }

    function test_afterExecute_noSpendLimit_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 100, "");
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        assertEq(fnSel, IExecutionHook.afterExecute.selector);
        vm.stopPrank();
    }

    function test_afterExecute_native_reverts_withExceededSpendLimit() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(0), SpendPeriod.Minute, 1);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(0), 100, "");
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        vm.expectRevert(ISpendingLimitHook.ExceededSpendLimit.selector);
        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        vm.stopPrank();
    }

    function test_afterExecute_reverts_withExceededSpendLimit() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), SpendPeriod.Minute, 1);

        Call memory call = buildTransferCall(address(tokenA), receiver, 100);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        vm.expectRevert(ISpendingLimitHook.ExceededSpendLimit.selector);
        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        vm.stopPrank();
    }

    function test_afterExecute_reverts_withExceededSpendLimit_fuzz(uint8 _period, uint256 limit, uint256 amount)
        public
    {
        vm.assume(_period < uint8(SpendPeriod.Year));
        SpendPeriod period = SpendPeriod(_period);

        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        AccountKeyHash accountKeyHash = p256Key.toKeyHash().wrap(address(signerAccount));

        vm.prank(address(signerAccount));
        // check that the spend limit is set
        vm.expectEmit(true, true, true, true);
        emit ISpendingLimitHook.SpendLimitSet(accountKeyHash, address(tokenA), period, limit);
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), period, limit);

        Call memory call = buildTransferCall(address(tokenA), receiver, amount);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        if (amount > limit) {
            vm.expectRevert(ISpendingLimitHook.ExceededSpendLimit.selector);
            fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        } else {
            fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
            assertEq(fnSel, IExecutionHook.afterExecute.selector);
        }
        vm.stopPrank();
    }

    function test_afterExecute_spendPeriod_reverts_withExceededSpendLimit() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), SpendPeriod.Minute, 1);

        Call memory call = buildTransferCall(address(tokenA), receiver, 1);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        // Transfer is OK because it's within the spend period and limit
        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        assertEq(fnSel, IExecutionHook.afterExecute.selector);

        (fnSel, beforeExecuteData) = spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        // Second transfer reverts because it's over the limit within the spend period
        vm.expectRevert(ISpendingLimitHook.ExceededSpendLimit.selector);
        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        vm.stopPrank();
    }

    function test_afterExecute_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), SpendPeriod.Minute, 1);

        Call memory call = buildTransferCall(address(tokenA), receiver, 1);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        assertEq(fnSel, IExecutionHook.afterExecute.selector);
        vm.stopPrank();
    }

    function test_afterExecute_spendPeriod_resets_succeeds() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        vm.prank(address(signerAccount));
        spendingLimitHook.setSpendLimit(p256Key.toKeyHash(), address(tokenA), SpendPeriod.Minute, 1);

        Call memory call = buildTransferCall(address(tokenA), receiver, 1);

        vm.startPrank(address(signerAccount));
        (bytes4 fnSel, bytes memory beforeExecuteData) =
            spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        assertEq(fnSel, IExecutionHook.afterExecute.selector);

        // Wait for the spend period to reset
        vm.warp(block.timestamp + 60);

        (fnSel, beforeExecuteData) = spendingLimitHook.beforeExecute(p256Key.toKeyHash(), address(tokenA), 0, call.data);
        assertEq(fnSel, IExecutionHook.beforeExecute.selector);

        fnSel = spendingLimitHook.afterExecute(p256Key.toKeyHash(), beforeExecuteData);
        assertEq(fnSel, IExecutionHook.afterExecute.selector);
        vm.stopPrank();
    }
}

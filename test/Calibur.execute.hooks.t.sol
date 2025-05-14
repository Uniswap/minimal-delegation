// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {ExecuteFixtures} from "./utils/ExecuteFixtures.sol";
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
import {IHook} from "../src/interfaces/IHook.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {KeyType, KeyLib, Key} from "../src/libraries/KeyLib.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {SignedBatchedCallLib, SignedBatchedCall} from "../src/libraries/SignedBatchedCallLib.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";
import {ICalibur} from "../src/interfaces/ICalibur.sol";
import {BaseAuthorization} from "../src/BaseAuthorization.sol";
import {BatchedCall} from "../src/libraries/BatchedCallLib.sol";
import {IGuardedExecutorHook} from "../src/hooks/execution/GuardedExecutorHook.sol";

contract CaliburExecuteHooksTest is TokenHandler, HookHandler, ExecuteFixtures, DelegationHandler {
    using TestKeyManager for TestKey;
    using KeyLib for Key;
    using CallUtils for *;
    using CallLib for Call[];
    using SignedBatchedCallLib for SignedBatchedCall;
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

    function test_execute_GuardedExecutorHook_beforeExecute_reverts() public {
        TestKey memory secp256k1Key = TestKeyManager.initDefault(KeyType.Secp256k1);

        // Ensure the key is registered and the hook is set
        vm.startPrank(address(signerAccount));
        signerAccount.register(secp256k1Key.toKey());
        signerAccount.update(secp256k1Key.toKeyHash(), SettingsBuilder.init().fromHook(IHook(address(guardedExecutorHook))));
        
        bytes4 fnSel = bytes4(keccak256("transfer(address,uint256)"));
        // Then, apply the restrictions on beforeExecute
        guardedExecutorHook.setCanExecute(secp256k1Key.toKeyHash(), address(tokenA), fnSel, false);
        vm.stopPrank();

        Call[] memory calls = CallUtils.initArray();
        calls = calls.push(buildTransferCall(address(tokenA), address(receiver), 1e18));

        BatchedCall memory batchedCall = CallUtils.initBatchedCall().withCalls(calls).withShouldRevert(true);

        vm.expectRevert(IGuardedExecutorHook.Unauthorized.selector);
        signerAccount.execute(batchedCall);    
    }
}
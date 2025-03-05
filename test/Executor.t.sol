// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Executor} from "../src/Executor.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";

contract MockExecutor is Executor {
    function setCanExecute(bytes32 keyHash, address target, bool can) public {
        _setCanExecute(keyHash, target, can);
    }

    function execute(bytes32 mode, Call[] calldata calls, bytes32 keyHash) public {
        _execute(mode, calls, keyHash);
    }
}

contract ExecutorTest is DelegationHandler {
    using CallBuilder for Call[];

    MockExecutor executor;
    bytes32 constant KEYHASH = keccak256("key");
    // batched call mode
    bytes32 constant MODE = 0x0100000000000000000000000000000000000000000000000000000000000000;

    error InvalidKeyHash();
    error InvalidTarget();

    function setUp() public {
        setUpDelegation();
        executor = new MockExecutor();
    }

    function test_setCanExecute_reverts_invalidKeyHash() public {
        vm.expectRevert(InvalidKeyHash.selector);
        executor.setCanExecute(bytes32(0), address(0), true);
    }

    function test_setCanExecute_reverts_invalidTarget() public {
        vm.expectRevert(InvalidTarget.selector);
        executor.setCanExecute(KEYHASH, address(executor), true);
    }

    // TODO: target == address(0) is potentially an edge case, since it is aliased to address(this) in lower level execute function call
    function test_setCanExecute_fuzz(uint160 seed, bytes4 selector, bool can) public {
        // Avoid address(0) and precompiles
        vm.assume(seed != 0);
        address target = address(uint160(seed) << 96);

        executor.setCanExecute(KEYHASH, target, can);

        Call[] memory calls = CallBuilder.init();
        calls = calls.push(CallBuilder.single(target, 0, abi.encodeWithSelector(selector)));
        assertEq(executor.canExecute(calls[0], KEYHASH), can);

        if (!can) vm.expectRevert(IERC7821.Unauthorized.selector);
        executor.execute(MODE, calls, KEYHASH);
    }
}

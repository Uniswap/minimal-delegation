// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {ExecuteHandler} from "./utils/ExecuteHandler.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {IMinimalDelegation} from "../src/interfaces/IMinimalDelegation.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {ModeDecoder} from "../src/libraries/ModeDecoder.sol";
import {ExecutionData, ExecutionDataLib} from "../src/libraries/ExecuteLib.sol";
import {Call, CallLib} from "../src/libraries/CallLib.sol";
import {KeyType, Key, KeyLib} from "../src/libraries/KeyLib.sol";

contract MinimalDelegationExecuteInvariantHandler is Test, ExecuteHandler {
    using TestKeyManager for TestKey;
    using ModeDecoder for bytes32;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using ExecutionDataLib for ExecutionData;

    IMinimalDelegation public signerAccount;

    address[] public callers;
    address public currentCaller;

    TestKey[] public keys;
    TestKey public currentSigningKey;

    // Ghost variables
    EnumerableSetLib.Bytes32Set internal _ghostKeyHashes;

    constructor(IMinimalDelegation _signerAccount, TestKey[] memory _keys, address[] memory _callers) {
        signerAccount = _signerAccount;
        for(uint256 i = 0; i < _keys.length; i++) {
            keys.push(_keys[i]);
        }
        callers = _callers;
    }

    /// Used to switch between which keys sign data
    modifier useSigningKey(uint256 keyIndexSeed) {
        currentSigningKey = keys[bound(keyIndexSeed, 0, keys.length - 1)];
        _;
    }

    /// Used to switch between callers of the signerAccount
    modifier useCaller(uint256 callerIndexSeed) {
        currentCaller = callers[bound(callerIndexSeed, 0, callers.length - 1)];
        vm.startPrank(currentCaller);
        _;
        vm.stopPrank();
    }

    function _boundCall(Call memory call) internal view returns (Call memory) {
        call.value = bound(call.value, 0, address(signerAccount).balance);
        return call;
    }

    function _nonceIsValid(uint256 nonce) internal view returns (bool) {
        uint64 seq = uint64(nonce);
        // getNonce casts to uint192
        return signerAccount.getNonce(nonce) + 1 == seq;
    }

    // TODO: support execution type
    function executeBatchedCall(Call calldata call, uint256 callerIndexSeed)
        public
        useCaller(callerIndexSeed)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = _boundCall(call);

        if (currentCaller != address(signerAccount)) {
            vm.expectRevert(IERC7821.Unauthorized.selector);
        }
        signerAccount.execute(BATCHED_CALL, abi.encode(calls));
    }

    /// Computes digest and signs correctly
    // TODO: add switch on caller for entrypoint vs. native bundler use case
    function executeWithOpData(Call calldata call, uint256 nonce, uint256 keyIndexSeed)
        public
        useSigningKey(keyIndexSeed)
    {
        Call[] memory calls = new Call[](1);
        calls[0] = _boundCall(call);

        bytes32 currentKeyHash = currentSigningKey.toKeyHash();

        // Build execution data
        ExecutionData memory executionData = ExecutionData({calls: calls, nonce: nonce});
        // Compute digest
        bytes32 digest = signerAccount.hashTypedData(executionData.hash());

        bytes memory signature = currentSigningKey.sign(digest);
        bytes memory wrappedSignature = abi.encode(currentKeyHash, signature);
        bytes memory opData = abi.encode(nonce, wrappedSignature);

        bool keyExists = _ghostKeyHashes.contains(currentKeyHash);
        bool nonceIsValid = _nonceIsValid(nonce);

        try signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, abi.encode(calls, opData)) {
        } catch (bytes memory revertData) {
            // Must be in order of occurrence
            if(!nonceIsValid) {
                assertEq(bytes4(revertData), INonceManager.InvalidNonce.selector);
            } else if (!keyExists) {
                assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
            } else {
                revert("uncaught revert");
            }
        }
    }

    function registerKey(uint256 keyIndexSeed) internal useSigningKey(keyIndexSeed) {
        vm.prank(address(signerAccount));
        signerAccount.authorize(currentSigningKey.toKey());
        
        _ghostKeyHashes.add(currentSigningKey.toKeyHash());
    }
}

contract MinimalDelegationExecuteInvariantTest is TokenHandler, DelegationHandler, ExecuteHandler {
    using KeyLib for Key;
    using TestKeyManager for TestKey;

    MinimalDelegationExecuteInvariantHandler public invariantHandler;

    address public untrustedCaller = makeAddr("untrustedCaller");
    uint256 public untrustedPrivateKey = 0xdead;

    // address who is calling the invariantHandler, shouldn't matter
    address internal sender = makeAddr("sender");

    TestKey[] internal _keys;

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        address[] memory callers = new address[](2);
        // Add trusted root caller
        callers[0] = address(signerAccount);
        // Add untrusted caller
        callers[1] = untrustedCaller;

        // Add trusted root key
        _keys.push(TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey));
        // Add untrusted key
        _keys.push(TestKeyManager.withSeed(KeyType.Secp256k1, untrustedPrivateKey));

        invariantHandler = new MinimalDelegationExecuteInvariantHandler(signerAccount, _keys, callers);

        targetContract(address(invariantHandler));
        targetSender(sender);
    }

    function invariant_executeNeverChangesKeyPermissions() public view {
        for(uint256 i = 0; i < _keys.length; i++) {
            TestKey memory key = _keys[i];
            bytes32 keyHash = key.toKeyHash();
            // assertEq(signerAccount.getKey(keyHash).hash(), keyHash);
        }
    }
}

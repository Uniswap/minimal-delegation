// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {ExecuteHandler} from "./utils/ExecuteHandler.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {IMinimalDelegation} from "../src/interfaces/IMinimalDelegation.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";
import {IKeyManagement} from "../src/interfaces/IKeyManagement.sol";
import {Call, CallLib} from "../src/libraries/CallLib.sol";
import {KeyType, Key, KeyLib} from "../src/libraries/KeyLib.sol";
import {HandlerCall, CallUtils} from "./utils/CallUtils.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {FunctionCallGenerator} from "./utils/FunctionCallGenerator.sol";
import {Settings, SettingsLib} from "../src/libraries/SettingsLib.sol";
import {SettingsBuilder} from "./utils/SettingsBuilder.sol";
import {SignedCalls, SignedCallsLib} from "../src/libraries/SignedCallsLib.sol";

// To avoid stack to deep
struct SetupParams {
    IMinimalDelegation _signerAccount;
    TestKey[] _keys;
    address[] _callers;
    address _tokenA;
    address _tokenB;
}

contract MinimalDelegationExecuteInvariantHandler is ExecuteHandler, FunctionCallGenerator {
    using TestKeyManager for TestKey;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call[];
    using CallUtils for Call;
    using CallUtils for Call[];
    using CallUtils for HandlerCall;
    using CallUtils for HandlerCall[];
    using SignedCallsLib for SignedCalls;
    using SettingsBuilder for Settings;

    address[] public callers;
    address public currentCaller;

    TestKey[] public keys;
    TestKey public currentSigningKey;

    ERC20Mock public tokenA;
    ERC20Mock public tokenB;

    IMinimalDelegation public signerAccount;

    constructor(SetupParams memory _params) FunctionCallGenerator(_params._tokenA, _params._tokenB) {
        signerAccount = _params._signerAccount;
        for (uint256 i = 0; i < _params._keys.length; i++) {
            keys.push(_params._keys[i]);
        }
        callers = _params._callers;
        tokenA = ERC20Mock(_params._tokenA);
        tokenB = ERC20Mock(_params._tokenB);
    }

    /// @notice Sets the current signing key for the test
    modifier useSigningKey(uint256 keyIndexSeed) {
        currentSigningKey = keys[_bound(keyIndexSeed, 0, keys.length - 1)];
        _;
    }

    /// @notice Sets the current caller for the test
    modifier useCaller(uint256 callerIndexSeed) {
        currentCaller = callers[_bound(callerIndexSeed, 0, callers.length - 1)];
        vm.startPrank(currentCaller);
        _;
        vm.stopPrank();
    }

    function _hash(Call[] memory calls, uint256 nonce) internal view returns (bytes32 digest) {
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        digest = signerAccount.hashTypedData(signedCalls.hash());
    }

    /// Helper function to get the next available nonce
    function _buildNextValidNonce(uint256 key) internal view returns (uint256 nonce, uint64 seq) {
        seq = uint64(signerAccount.getSeq(key));
        nonce = key << 64 | seq;
    }

    function _signingKeyIsRootEOA(TestKey memory key) internal view returns (bool) {
        return vm.addr(key.privateKey) == address(signerAccount);
    }

    function _registerSigningKeyIfNotRegistered(TestKey memory key) internal {
        if (!_ghostKeyHashes.contains(key.toKeyHash())) {
            vm.prank(address(signerAccount));
            signerAccount.register(key.toKey());
        }
    }

    /// @notice Executes a batched call with the current caller
    /// @dev Handler function meant to be called during invariant tests
    /// Generates random handler calls, executes them, then processes any registeredcallbacks
    function executeBatchedCall(uint256 seed) public useCaller(seed) {
        HandlerCall[] memory handlerCalls = _generateRandomHandlerCalls(seed, 0);

        try signerAccount.execute(BATCHED_CALL, abi.encode(handlerCalls.toCalls())) {
            _processCallbacks(handlerCalls);
        } catch (bytes memory revertData) {
            if (currentCaller != address(signerAccount)) {
                assertEq(bytes4(revertData), IERC7821.Unauthorized.selector);
            } else {
                revert("uncaught revert");
            }
        }
    }

    /// @notice Executes a call with operation data (with signature)
    /// @dev Handler function meant to be called during invariant tests
    /// Generates random handler calls, executes them, then processes any registeredcallbacks
    function executeWithOpData(uint192 nonceKey, uint256 seed) public useSigningKey(seed) {
        bytes32 currentKeyHash = currentSigningKey.toKeyHash();
        if (_signingKeyIsRootEOA(currentSigningKey)) {
            currentKeyHash = bytes32(0);
        } else {
            _registerSigningKeyIfNotRegistered(currentSigningKey);
        }

        HandlerCall[] memory handlerCalls = _generateRandomHandlerCalls(seed, 0);

        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        Call[] memory calls = handlerCalls.toCalls();

        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(nonce).hash());
        bytes memory wrappedSignature = abi.encode(currentKeyHash, currentSigningKey.sign(digest));
        bytes memory opData = abi.encode(nonce, wrappedSignature);
        bytes memory executionData = abi.encode(calls, opData);

        try signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData) {
            _processCallbacks(handlerCalls);
        } catch (bytes memory revertData) {
            bytes memory debugCalldata =
                abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL_SUPPORTS_OPDATA, executionData);
            console2.logBytes(debugCalldata);
            console2.logBytes(revertData);
            revert("uncaught revert");
        }
    }
}

/// @title MinimalDelegationExecuteInvariantTest
contract MinimalDelegationExecuteInvariantTest is TokenHandler, DelegationHandler {
    using KeyLib for Key;
    using TestKeyManager for TestKey;
    using CallUtils for Call;
    using CallUtils for Call[];
    using WrappedDataHash for bytes32;

    MinimalDelegationExecuteInvariantHandler internal invariantHandler;

    address public untrustedCaller = makeAddr("untrustedCaller");
    uint256 public untrustedPrivateKey = 0xdead;

    address internal sender = makeAddr("sender");

    TestKey[] internal _keys;
    TestKey internal untrustedKey;

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);

        address[] memory callers = new address[](2);
        // Add trusted root caller
        callers[0] = address(signerAccount);
        vm.label(callers[0], "signerAccount");
        // Add untrusted caller
        callers[1] = untrustedCaller;
        vm.label(callers[1], "untrustedCaller");

        untrustedKey = TestKeyManager.withSeed(KeyType.Secp256k1, untrustedPrivateKey);

        // Add trusted root key
        _keys.push(TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey));
        // Add untrusted key
        _keys.push(untrustedKey);

        SetupParams memory params = SetupParams({
            _signerAccount: signerAccount,
            _keys: _keys,
            _callers: callers,
            _tokenA: address(tokenA),
            _tokenB: address(tokenB)
        });
        invariantHandler = new MinimalDelegationExecuteInvariantHandler(params);

        // Explicitly target the wrapped execute functions in the handler
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MinimalDelegationExecuteInvariantHandler.executeBatchedCall.selector;
        selectors[1] = MinimalDelegationExecuteInvariantHandler.executeWithOpData.selector;
        FuzzSelector memory selector = FuzzSelector({addr: address(invariantHandler), selectors: selectors});

        targetSelector(selector);
        targetContract(address(invariantHandler));

        // Sender is the address used to call the invariantHandler, not important
        targetSender(sender);
    }

    /// @notice Verifies that the root key can always revoke other keys
    function invariant_rootKeyCanAlwaysRevokeOtherSigningKeys() public {
        // Ensure key exists
        bytes32 keyHash = untrustedKey.toKeyHash();
        try signerAccount.getKey(keyHash) {
            vm.prank(address(signerAccount));
            signerAccount.revoke(keyHash);
        } catch (bytes memory revertData) {
            assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
        }
    }

    /// @notice Verifies that the root key can always update other keys
    function invariant_rootKeyCanAlwaysUpdateOtherSigningKeys() public {
        bytes32 keyHash = untrustedKey.toKeyHash();
        try signerAccount.getKey(keyHash) {
            vm.prank(address(signerAccount));
            signerAccount.update(keyHash, SettingsBuilder.init());
        } catch (bytes memory revertData) {
            assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
        }
    }

    /// @notice Verifies that the root key can always register other signing keys
    function invariant_rootKeyCanAlwaysRegisterOtherSigningKeys() public {
        TestKey memory newKey = TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint());
        vm.prank(address(signerAccount));
        signerAccount.register(newKey.toKey());
        assertEq(signerAccount.getKey(newKey.toKeyHash()).hash(), newKey.toKeyHash());
    }
}

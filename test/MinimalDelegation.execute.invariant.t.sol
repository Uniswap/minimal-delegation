// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {Test} from "forge-std/Test.sol";
import {TokenHandler} from "./utils/TokenHandler.sol";
import {ExecuteFixtures} from "./utils/ExecuteFixtures.sol";
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
    TestKey[] _signingKeys;
    address _tokenA;
    address _tokenB;
}

contract MinimalDelegationExecuteInvariantHandler is ExecuteFixtures, FunctionCallGenerator {
    using TestKeyManager for TestKey;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call[];
    using CallUtils for *;
    using SignedCallsLib for SignedCalls;
    using SettingsBuilder for Settings;
    using SettingsLib for Settings;

    /// @notice The keys which will be used to sign calls to execute
    TestKey[] public signingKeys;
    TestKey public currentSigningKey;

    ERC20Mock public tokenA;
    ERC20Mock public tokenB;

    constructor(SetupParams memory _params)
        FunctionCallGenerator(_params._signerAccount, _params._tokenA, _params._tokenB)
    {
        for (uint256 i = 0; i < _params._signingKeys.length; i++) {
            signingKeys.push(_params._signingKeys[i]);
        }
        tokenA = ERC20Mock(_params._tokenA);
        tokenB = ERC20Mock(_params._tokenB);
    }

    /// @notice Sets the current key for the test
    /// if the test uses `caller`, we prank the key's public key
    modifier useKey(uint256 keyIndexSeed) {
        uint256 index;
        (currentSigningKey, index) = _rand(signingKeys, keyIndexSeed);
        _;
    }

    /// Helper function to get the next available nonce
    function _buildNextValidNonce(uint256 key) internal view returns (uint256 nonce, uint64 seq) {
        seq = uint64(signerAccount.getSeq(key));
        nonce = key << 64 | seq;
    }

    /// @notice Sets the tracked revert data if it is not already set
    function _trackRevert(bytes memory revertData, bytes memory trackedRevertData) internal pure returns (bytes memory) {
        if (trackedRevertData.length == 0) {
            trackedRevertData = revertData;
        }
        return trackedRevertData;
    }

    /// @notice Executes a batched call with the current caller
    /// @dev Handler function meant to be called during invariant tests
    /// TODO: only supports single call arrays for now
    /// - Generates a random call, executes it, then processes any registered callbacks
    /// - Any reverts are expected by the generated handler call
    function executeBatchedCall(uint256 generatorSeed, uint256 signerSeed) public useKey(signerSeed) {
        address caller = vm.addr(currentSigningKey.privateKey);
        vm.startPrank(caller);
        HandlerCall memory handlerCall = _generateHandlerCall(generatorSeed);
        HandlerCall[] memory handlerCalls = CallUtils.initHandler().push(handlerCall);

        try signerAccount.execute(BATCHED_CALL, abi.encode(handlerCalls.toCalls())) {
            _processCallbacks(handlerCalls);
        } catch (bytes memory revertData) {
            if (caller != address(signerAccount)) {
                assertEq(bytes4(revertData), IERC7821.Unauthorized.selector);
            } else if (handlerCall.revertData.length > 0) {
                assertEq(revertData, handlerCall.revertData);
            } else {
                revert("uncaught revert");
            }
        }

        vm.stopPrank();
    }

    /// @notice Executes a call with operation data (with signature)
    /// @dev Handler function meant to be called during invariant tests
    /// TODO: only supports single call arrays for now
    /// - If the signing key is not registered on the account, expect the call to revert
    function executeWithOpData(uint192 nonceKey, uint256 generatorSeed, uint256 signerSeed) public useKey(signerSeed) {
        bool isRootKey = vm.addr(currentSigningKey.privateKey) == address(signerAccount);
        bytes32 currentKeyHash = currentSigningKey.toKeyHash();

        HandlerCall memory handlerCall = _generateHandlerCall(generatorSeed);
        HandlerCall[] memory handlerCalls = CallUtils.initHandler().push(handlerCall);
        (uint256 nonce,) = _buildNextValidNonce(nonceKey);
        Call[] memory calls = handlerCalls.toCalls();

        bytes32 digest = signerAccount.hashTypedData(calls.toSignedCalls(nonce).hash());
        bytes memory wrappedSignature =
            abi.encode(isRootKey ? KeyLib.ROOT_KEY_HASH : currentKeyHash, currentSigningKey.sign(digest));
        bytes memory opData = abi.encode(nonce, wrappedSignature);
        bytes memory executionData = abi.encode(calls, opData);

        // Track just the first expected revert
        bytes memory expectedRevert;
        // Signature validation reverts happen first
        if (!isRootKey) {
            try signerAccount.getKey(currentKeyHash) {
                Settings settings = signerAccount.getKeySettings(currentKeyHash);
                // Expect revert if expired
                (bool isExpired,) = settings.isExpired();
                if (isExpired) {
                    expectedRevert =
                        _trackRevert(abi.encodeWithSelector(IKeyManagement.KeyExpired.selector), expectedRevert);
                } else if (!settings.isAdmin() && calls.containsSelfCall()) {
                    expectedRevert = _trackRevert(
                        abi.encodeWithSelector(IKeyManagement.OnlyAdminCanSelfCall.selector), expectedRevert
                    );
                }
            } catch (bytes memory revertData) {
                assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
                expectedRevert =
                    _trackRevert(abi.encodeWithSelector(IKeyManagement.KeyDoesNotExist.selector), expectedRevert);
            }
        }
        // Handler call reverts
        if (handlerCall.revertData.length > 0) {
            expectedRevert = _trackRevert(handlerCall.revertData, expectedRevert);
        }

        try signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, executionData) {
            _processCallbacks(handlerCalls);
        } catch (bytes memory revertData) {
            if (expectedRevert.length > 0) {
                assertEq(revertData, expectedRevert);
            } else {
                bytes memory debugCalldata =
                    abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL_SUPPORTS_OPDATA, executionData);
                console2.logBytes(debugCalldata);
                console2.logBytes(revertData);
                revert("uncaught revert");
            }
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

    function setUp() public {
        setUpDelegation();
        setUpTokens();

        vm.deal(address(signerAccount), 100e18);
        tokenA.mint(address(signerAccount), 100e18);
        tokenB.mint(address(signerAccount), 100e18);

        TestKey[] memory _signingKeys = new TestKey[](2);
        // Add trusted root key
        _signingKeys[0] = TestKeyManager.withSeed(KeyType.Secp256k1, signerPrivateKey);
        // Add untrusted key
        _signingKeys[1] = TestKeyManager.withSeed(KeyType.Secp256k1, untrustedPrivateKey);

        SetupParams memory params = SetupParams({
            _signerAccount: signerAccount,
            _signingKeys: _signingKeys,
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

    /// Function called after each invariant test
    function afterInvariant() view public {
        console2.log("Number of persisted registered keys");
        console2.logUint(signerAccount.keyCount());

        invariantHandler.logState();
    }

    /// @notice Verifies that the root key can always register other signing keys
    function invariant_rootKeyCanAlwaysRegisterOtherSigningKeys() public {
        TestKey memory newKey = TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint());
        vm.prank(address(signerAccount));
        signerAccount.register(newKey.toKey());
        assertEq(signerAccount.getKey(newKey.toKeyHash()).hash(), newKey.toKeyHash());
    }

    function invariant_keyStateIsConsistent() public view {
        // Iterate over keyHashes
        uint256 keyCount = signerAccount.keyCount();
        for (uint256 i = 0; i < keyCount; i++) {
            // Will revert if key does not exist
            Key memory key = signerAccount.keyAt(i);
            bytes32 keyHash = key.hash();
            // Will be false if the stored encoded data is wrong
            assertEq(signerAccount.getKey(keyHash).hash(), keyHash);
        }
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

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
import {ModeDecoder} from "../src/libraries/ModeDecoder.sol";
import {Call, CallLib} from "../src/libraries/CallLib.sol";
import {SignedCalls, SignedCallsLib} from "../src/libraries/SignedCallsLib.sol";
import {KeyType, Key, KeyLib} from "../src/libraries/KeyLib.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {HandlerCall, HandlerCallLib} from "./utils/HandlerCallLib.sol";

struct SetupParams {
    IMinimalDelegation _signerAccount;
    TestKey[] _keys;
    address[] _callers;
    address _tokenA;
    address _tokenB;
}

interface IHandlerGhostCallbacks {
    function ghost_RegisterCallback(Key memory key) external;
}

contract MinimalDelegationExecuteInvariantHandler is Test, ExecuteHandler {
    using TestKeyManager for TestKey;
    using KeyLib for Key;
    using ModeDecoder for bytes32;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using SignedCallsLib for SignedCalls;
    using CallBuilder for Call;
    using CallBuilder for Call[];
    using HandlerCallLib for HandlerCall;
    using HandlerCallLib for HandlerCall[];

    IMinimalDelegation public signerAccount;

    address[] public callers;
    address public currentCaller;

    TestKey[] public keys;
    TestKey public currentSigningKey;

    // Ghost variables to track registered keys
    EnumerableSetLib.Bytes32Set internal _ghostKeyHashes;

    ERC20Mock public tokenA;
    ERC20Mock public tokenB;

    constructor(SetupParams memory _params) {
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
        currentSigningKey = keys[bound(keyIndexSeed, 0, keys.length - 1)];
        _;
    }

    /// @notice Sets the current caller for the test
    modifier useCaller(uint256 callerIndexSeed) {
        currentCaller = callers[bound(callerIndexSeed, 0, callers.length - 1)];
        vm.startPrank(currentCaller);
        _;
        vm.stopPrank();
    }

    /// @notice Bounds call value to the account balance
    function _boundCall(Call memory call) internal view returns (Call memory) {
        call.value = bound(call.value, 0, address(signerAccount).balance);
        return call;
    }

    /// @notice Selects a random element from an array
    function _randFromArray(bytes32[] memory array) internal view returns (bytes32) {
        return array[bound(uint256(0), 0, array.length - 1)];
    }

    /// @notice Selects a random element from an array
    function _randFromArray(Key[] memory array) internal view returns (Key memory) {
        return array[bound(uint256(0), 0, array.length - 1)];
    }

    /// @notice Selects a random element from an array
    function _randFromArray(HandlerCall[] memory array) internal view returns (HandlerCall memory) {
        return array[bound(uint256(0), 0, array.length - 1)];
    }

    /// @notice Builds the next valid nonce for the given key
    function _buildNextValidNonce(uint256 key) internal view returns (uint256 nonce, uint64 seq) {
        seq = uint64(signerAccount.getSeq(key));
        nonce = key << 64 | seq;
    }

    /// @notice Checks if the signing key is the root EOA
    function _signingKeyIsRootEOA(TestKey memory key) internal view returns (bool) {
        return vm.addr(key.privateKey) == address(signerAccount);
    }

    /// @notice Executes registered callbacks for handler calls
    function _doCallbacks(HandlerCall[] memory handlerCalls) internal {
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            if (handlerCalls[i].callback.length > 0) {
                (bool success,) = address(this).call(handlerCalls[i].callback);
                assertEq(success, true);
            }
        }
    }

    /// @notice Ghost callback to track registered keys
    function ghost_RegisterCallback(Key memory key) public {
        _ghostKeyHashes.add(key.hash());
    }

    /// @notice Creates handler calls for the test
    function _getHandlerCalls() internal returns (HandlerCall[] memory) {
        HandlerCall[] memory handlerCalls = HandlerCallLib.init();

        // Add register calls for all tracked keys
        Key[] memory _keys = _getKeys();
        for (uint256 i = 0; i < _keys.length; i++) {
            handlerCalls = handlerCalls.push(
                HandlerCallLib.initDefault().withCall(
                    CallBuilder.initDefault().withTo(address(signerAccount)).withData(_dataRegister(_keys[i]))
                ).withCallback(abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_RegisterCallback.selector, _keys[i]))
            );
        }

        // Add transfer calls for all tracked tokens
        handlerCalls = handlerCalls.push(
            HandlerCallLib.initDefault().withCall(
                CallBuilder.initDefault().withTo(address(tokenA)).withData(
                    abi.encodeWithSelector(ERC20.transfer.selector, vm.randomAddress(), 1)
                )
            )
        );
        handlerCalls = handlerCalls.push(
            HandlerCallLib.initDefault().withCall(
                CallBuilder.initDefault().withTo(address(tokenB)).withData(
                    abi.encodeWithSelector(ERC20.transfer.selector, vm.randomAddress(), 1)
                )
            )
        );

        return handlerCalls;
    }

    /// @notice Loads keys into memory
    function _getKeys() internal view returns (Key[] memory) {
        Key[] memory _keys = new Key[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            _keys[i] = keys[i].toKey();
        }
        return _keys;
    }

    /// @notice Executes a batched call with the current caller
    function executeBatchedCall(uint256 callerIndexSeed) public useCaller(callerIndexSeed) {
        HandlerCall[] memory handlerCalls = _getHandlerCalls();
        HandlerCall memory handlerCall = _randFromArray(handlerCalls);

        Call[] memory calls = new Call[](1);
        calls[0] = handlerCall.call;

        try signerAccount.execute(BATCHED_CALL, abi.encode(calls)) {
            HandlerCall[] memory _callbacks = new HandlerCall[](1);
            _callbacks[0] = handlerCall;
            _doCallbacks(_callbacks);
        } catch (bytes memory revertData) {
            if (currentCaller != address(signerAccount)) {
                assertEq(bytes4(revertData), IERC7821.Unauthorized.selector);
            } else {
                revert("uncaught revert");
            }
        }
    }

    /// @notice Executes a call with operation data (with signature)
    function executeWithOpData(uint192 nonceKey, uint256 keyIndexSeed) public useSigningKey(keyIndexSeed) {
        HandlerCall[] memory handlerCalls = _getHandlerCalls();
        HandlerCall memory handlerCall = _randFromArray(handlerCalls);

        Call[] memory calls = new Call[](1);
        calls[0] = handlerCall.call;

        bytes32 currentKeyHash = _signingKeyIsRootEOA(currentSigningKey) ? bytes32(0) : currentSigningKey.toKeyHash();

        (uint256 nonce,) = _buildNextValidNonce(nonceKey);

        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        // Compute digest
        bytes32 digest = signerAccount.hashTypedData(signedCalls.hash());

        bytes memory signature = currentSigningKey.sign(digest);
        bytes memory wrappedSignature = abi.encode(currentKeyHash, signature);
        bytes memory opData = abi.encode(nonce, wrappedSignature);

        bool keyExists = _ghostKeyHashes.contains(currentKeyHash);

        try signerAccount.execute(BATCHED_CALL_SUPPORTS_OPDATA, abi.encode(calls, opData)) {
            HandlerCall[] memory _callbacks = new HandlerCall[](1);
            _callbacks[0] = handlerCall;
            _doCallbacks(_callbacks);
        } catch (bytes memory revertData) {
            // Must be in order of occurrence
            if (!keyExists) {
                assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
            } else {
                revert("uncaught revert");
            }
        }
    }
}

contract MinimalDelegationExecuteInvariantTest is TokenHandler, DelegationHandler, ExecuteHandler {
    using KeyLib for Key;
    using TestKeyManager for TestKey;
    using CallBuilder for Call;
    using CallBuilder for Call[];
    using WrappedDataHash for bytes32;

    MinimalDelegationExecuteInvariantHandler public invariantHandler;

    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

    address public untrustedCaller = makeAddr("untrustedCaller");
    uint256 public untrustedPrivateKey = 0xdead;

    // Address calling the invariantHandler
    address internal sender = makeAddr("sender");

    TestKey[] internal _keys;
    TestKey internal untrustedKey;

    function setUp() public {
        setUpDelegation();
        setUpTokens();

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

        targetContract(address(invariantHandler));
        targetSender(sender);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IHandlerGhostCallbacks.ghost_RegisterCallback.selector;
        FuzzSelector memory selector = FuzzSelector({addr: address(invariantHandler), selectors: selectors});
        excludeSelector(selector);
    }

    /// @notice Verifies that the root key can always revoke other keys
    function invariant_rootKeyCanAlwaysRevokeOtherKeys() public {
        // Ensure key exists
        bytes32 keyHash = untrustedKey.toKeyHash();
        try signerAccount.getKey(keyHash) {
            vm.prank(address(signerAccount));
            signerAccount.revoke(keyHash);
        } catch (bytes memory revertData) {
            assertEq(bytes4(revertData), IKeyManagement.KeyDoesNotExist.selector);
        }
    }
}

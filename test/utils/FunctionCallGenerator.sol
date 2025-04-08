// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Key, KeyLib, KeyType} from "../../src/libraries/KeyLib.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";
import {HandlerCall, CallUtils} from "./CallUtils.sol";
import {ExecuteHandler} from "./ExecuteHandler.sol";
import {GhostStateTracker} from "./GhostStateTracker.sol";
import {IHandlerGhostCallbacks} from "./GhostStateTracker.sol";

/**
 * @title FunctionCallGenerator
 * @dev Helper contract to generate random function calls for MinimalDelegation invariant testing
 */
abstract contract FunctionCallGenerator is Test, GhostStateTracker {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallUtils for Call;
    using CallUtils for Call[];
    using CallUtils for HandlerCall;
    using CallUtils for HandlerCall[];
    using TestKeyManager for TestKey;

    uint256 public constant FUNCTION_REGISTER = 0;
    uint256 public constant FUNCTION_REVOKE = 1;
    uint256 public constant FUNCTION_UPDATE = 2;
    uint256 public constant TRANSFER_TOKEN = 3;
    uint256 public constant FUNCTION_COUNT = 4;

    uint256 public constant MAX_DEPTH = 5;
    uint256 public constant MAX_KEYS = 10;

    address private immutable _tokenA;
    address private immutable _tokenB;

    // Keys that will be operated over in generated calldata
    TestKey[] public fixture_testKeys;

    EnumerableSetLib.Bytes32Set internal pendingRegisteredKeys;

    constructor(address tokenA, address tokenB) {
        _tokenA = tokenA;
        _tokenB = tokenB;

        // Generate MAX_KEYS and add to fixtureKey
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            fixture_testKeys.push(TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint()));
        }
    }

    function _rand(TestKey[] storage keys, uint256 seed) internal view returns (TestKey memory) {
        return keys[seed % keys.length];
    }

    function _wrapCallFailedRevertData(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC7821.CallFailed.selector, abi.encodePacked(selector));
    }

    /// @return calldata to register a new key along with its callback
    function _registerCall(TestKey memory newKey, bool isRegistered) internal virtual returns (HandlerCall memory) {
        // No error is thrown if the key is already registered, so ignore
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRegisterCall(newKey)).withCallback(
            abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_RegisterCallback.selector, newKey.toKey())
        );
    }

    /// @return calldata to revoke a key along with its callback
    function _revokeCall(bytes32 keyHash, bool isRegistered) internal virtual returns (HandlerCall memory) {
        bytes memory revertData =
            isRegistered ? bytes("") : _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRevokeCall(keyHash)).withCallback(
            abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_RevokeCallback.selector, keyHash)
        ).withRevertData(revertData);
    }

    /// @return calldata to update a key along with its callback
    function _updateCall(bytes32 keyHash, Settings settings, bool isRegistered)
        internal
        virtual
        returns (HandlerCall memory)
    {
        bytes memory revertData =
            isRegistered ? bytes("") : _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeUpdateCall(keyHash, settings)).withCallback(
            abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_UpdateCallback.selector, keyHash, settings)
        ).withRevertData(revertData);
    }

    /// @return calldata to transfer tokens
    function _tokenTransferCall(address token, address to, uint256 amount)
        internal
        virtual
        returns (HandlerCall memory)
    {
        return CallUtils.initHandlerDefault().withCall(
            CallUtils.initDefault().withTo(token).withData(abi.encodeWithSelector(ERC20.transfer.selector, to, amount))
        );
    }

    // Ghost keys are persisted after the callbacks are triggered
    function _getRandomGhostKeyHash(uint256 seed) internal view returns (bytes32) {
        if (_lastKnownKeyHashes.values().length == 0) {
            return bytes32(0);
        }
        return _lastKnownKeyHashes.values()[seed % _lastKnownKeyHashes.values().length];
    }

    /**
     * @notice Generate a random function call with equal weighting between function types
     * @param randomSeed Random seed for generation
     * @return A call object for the generated function
     */
    function _generateHandlerCall(uint256 randomSeed) public returns (HandlerCall memory) {
        vm.assume(randomSeed < type(uint256).max);
        // Select function type with equal weighting
        uint256 functionType = _bound(randomSeed, 0, FUNCTION_COUNT - 1);

        TestKey memory testKey = _rand(fixture_testKeys, randomSeed);
        bytes32 keyHash = testKey.toKeyHash();

        bool isRegistered = _lastKnownKeyHashes.contains(keyHash);
        if (!isRegistered) {
            isRegistered = pendingRegisteredKeys.contains(keyHash);
        }

        // REGISTER
        if (functionType == FUNCTION_REGISTER) {
            pendingRegisteredKeys.add(keyHash);
            return _registerCall(testKey, isRegistered);
        }
        // REVOKE
        else if (functionType == FUNCTION_REVOKE) {
            pendingRegisteredKeys.remove(keyHash);
            return _revokeCall(keyHash, isRegistered);
        }
        // UPDATE
        else if (functionType == FUNCTION_UPDATE) {
            // TODO: fuzz settings
            return _updateCall(keyHash, Settings.wrap(0), isRegistered);
        } else {
            return _tokenTransferCall(_tokenA, vm.randomAddress(), 1);
        }
    }

    /**
     * @notice Generate an array of random function calls
     * @param seed Random seed for generation
     * @param depth Current recursion depth
     * @return An array of call objects
     */
    function _generateHandlerCalls(uint256 seed, uint256 depth) internal returns (HandlerCall[] memory) {
        // How many calls to generate (more at lower depths)
        uint256 cnt = _bound(seed % 10, 1, MAX_DEPTH - depth + 1);

        HandlerCall[] memory handlerCalls = new HandlerCall[](cnt);
        for (uint256 i = 0; i < cnt; i++) {
            handlerCalls[i] = _generateHandlerCall(uint256(keccak256(abi.encode(seed, i))));
        }

        return handlerCalls;
    }

    /// @notice Executes registered callbacks for handler calls
    function _processCallbacks(HandlerCall[] memory handlerCalls) internal {
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            if (handlerCalls[i].callback.length > 0) {
                (bool success, bytes memory revertData) = address(this).call(handlerCalls[i].callback);
                if (!success) {
                    console2.log("revertData");
                    console2.logBytes(revertData);
                }
                assertEq(success, true);
            }
        }
    }
}

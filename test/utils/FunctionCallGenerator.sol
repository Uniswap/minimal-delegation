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
import {IInvariantStateTracker, InvariantStateTracker} from "./InvariantStateTracker.sol";
import {IMinimalDelegation} from "../../src/interfaces/IMinimalDelegation.sol";

/**
 * @title FunctionCallGenerator
 * @dev Helper contract to generate random function calls for MinimalDelegation invariant testing
 */
abstract contract FunctionCallGenerator is Test, InvariantStateTracker {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallUtils for Call;
    using CallUtils for Call[];
    using CallUtils for HandlerCall;
    using CallUtils for HandlerCall[];
    using TestKeyManager for TestKey;

    uint256 public constant FUZZED_FUNCTION_COUNT = 3;

    uint256 public constant MAX_DEPTH = 5;
    uint256 public constant MAX_KEYS = 10;

    IMinimalDelegation internal immutable signerAccount;
    address private immutable _tokenA;
    address private immutable _tokenB;

    // Keys that will be operated over in generated calldata
    TestKey[] public fixture_testKeys;

    constructor(IMinimalDelegation _signerAccount, address tokenA, address tokenB) {
        signerAccount = _signerAccount;
        _tokenA = tokenA;
        _tokenB = tokenB;

        // Generate MAX_KEYS and add to fixtureKey
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            fixture_testKeys.push(TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint()));
        }
    }

    function _rand(TestKey[] storage keys, uint256 seed) internal view returns (TestKey memory, uint256) {
        return (keys[seed % keys.length], seed % keys.length);
    }

    function _wrapCallFailedRevertData(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC7821.CallFailed.selector, abi.encodePacked(selector));
    }

    /// @return calldata to register a new key along with its callback
    function _registerCall(TestKey memory newKey, bytes memory revertData)
        internal
        virtual
        returns (HandlerCall memory)
    {
        // No error is thrown if the key is already registered, so ignore
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRegisterCall(newKey)).withCallback(
            abi.encodeWithSelector(IInvariantStateTracker.registerCallback.selector, newKey.toKey())
        ).withRevertData(revertData);
    }

    /// @return calldata to revoke a key along with its callback
    function _revokeCall(bytes32 keyHash, bytes memory revertData) internal virtual returns (HandlerCall memory) {
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRevokeCall(keyHash)).withCallback(
            abi.encodeWithSelector(IInvariantStateTracker.revokeCallback.selector, keyHash)
        ).withRevertData(revertData);
    }

    /// @return calldata to update a key along with its callback
    function _updateCall(bytes32 keyHash, Settings settings, bytes memory revertData)
        internal
        virtual
        returns (HandlerCall memory)
    {
        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeUpdateCall(keyHash, settings)).withCallback(
            abi.encodeWithSelector(IInvariantStateTracker.updateCallback.selector, keyHash, settings)
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

    /**
     * @notice Generate a random function call with equal weighting between function types
     * @param randomSeed Random seed for generation
     * @return A call object for the generated function
     */
    function _generateHandlerCall(uint256 randomSeed) public returns (HandlerCall memory) {
        (TestKey memory testKey, uint256 index) = _rand(fixture_testKeys, randomSeed);
        bytes32 keyHash = testKey.toKeyHash();

        bool isRegistered;
        try signerAccount.getKey(keyHash) {
            isRegistered = true;
        } catch (bytes memory _revertData) {
            assertEq(bytes4(_revertData), IKeyManagement.KeyDoesNotExist.selector);
            isRegistered = false;
        }

        bytes memory revertData;

        // REGISTER == 0
        if (randomSeed % FUZZED_FUNCTION_COUNT == 0) {
            console2.log("register key #%s", index);
            return _registerCall(testKey, revertData);
        }
        // REVOKE == 1
        else if (randomSeed % FUZZED_FUNCTION_COUNT == 1) {
            if (!isRegistered) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
            }
            console2.log("revoke key #%s, expecting revert %s", index, revertData.length > 0);
            return _revokeCall(keyHash, revertData);
        }
        // UPDATE == 2
        else if (randomSeed % FUZZED_FUNCTION_COUNT == 2) {
            if (!isRegistered) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
            }
            console2.log("update key #%s, expecting revert %s", index, revertData.length > 0);
            // TODO: fuzz settings
            return _updateCall(keyHash, Settings.wrap(0), revertData);
        } else {
            console2.log("token transfer key #%s", index);
            return _tokenTransferCall(_tokenA, vm.randomAddress(), 1);
        }
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

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
import {ExecuteFixtures} from "./ExecuteFixtures.sol";
import {IInvariantCallbacks, InvariantFixtures} from "./InvariantFixtures.sol";
import {IMinimalDelegation} from "../../src/interfaces/IMinimalDelegation.sol";
import {SettingsBuilder} from "./SettingsBuilder.sol";
import {SignedBatchedCall} from "../../src/libraries/SignedBatchedCallLib.sol";
import {BatchedCall} from "../../src/libraries/BatchedCallLib.sol";

/**
 * @title FunctionCallGenerator
 * @dev Helper contract to generate random function calls for MinimalDelegation invariant testing
 */
abstract contract FunctionCallGenerator is InvariantFixtures {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallUtils for *;
    using TestKeyManager for TestKey;
    using SettingsBuilder for Settings;

    uint256 public constant FUZZED_FUNCTION_COUNT = 3;

    /// Member variables passed in by inheriting contract
    IMinimalDelegation internal signerAccount;
    address private immutable _tokenA;
    address private immutable _tokenB;

    constructor(IMinimalDelegation _signerAccount, address tokenA, address tokenB) {
        signerAccount = _signerAccount;
        _tokenA = tokenA;
        _tokenB = tokenB;
    }

    function _testKeyIsSignerAccount(TestKey memory testKey) internal view returns (bool) {
        return vm.addr(testKey.privateKey) == address(signerAccount);
    }

    function _wrapCallFailedRevertData(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IMinimalDelegation.CallFailed.selector, abi.encodePacked(selector));
    }

    /// @return calldata to register a new key along with its callback
    function _registerCall(TestKey memory newKey, bytes memory revertData)
        internal
        virtual
        returns (HandlerCall memory)
    {
        if (revertData.length > 0) _state.registerReverted++;

        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRegisterCall(newKey)).withCallback(
            abi.encodeWithSelector(IInvariantCallbacks.registerCallback.selector, newKey.toKey())
        ).withRevertData(revertData);
    }

    /// @return calldata to revoke a key along with its callback
    function _revokeCall(bytes32 keyHash, bytes memory revertData) internal virtual returns (HandlerCall memory) {
        if (revertData.length > 0) _state.revokeReverted++;

        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeRevokeCall(keyHash)).withCallback(
            abi.encodeWithSelector(IInvariantCallbacks.revokeCallback.selector, keyHash)
        ).withRevertData(revertData);
    }

    /// @return calldata to update a key along with its callback
    function _updateCall(bytes32 keyHash, Settings settings, bytes memory revertData)
        internal
        virtual
        returns (HandlerCall memory)
    {
        if (revertData.length > 0) _state.updateReverted++;

        return CallUtils.initHandlerDefault().withCall(CallUtils.encodeUpdateCall(keyHash, settings)).withCallback(
            abi.encodeWithSelector(IInvariantCallbacks.updateCallback.selector, keyHash, settings)
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
    function _generateHandlerCall(uint256 randomSeed) internal returns (HandlerCall memory) {
        TestKey memory testKey = _randKeyFromArray(fixtureKeys);
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
            if (_testKeyIsSignerAccount(testKey)) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.CannotRegisterRootKey.selector);
            }
            return _registerCall(testKey, revertData);
        }
        // REVOKE == 1
        else if (randomSeed % FUZZED_FUNCTION_COUNT == 1) {
            if (!isRegistered) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
            }
            return _revokeCall(keyHash, revertData);
        }
        // UPDATE == 2
        else if (randomSeed % FUZZED_FUNCTION_COUNT == 2) {
            Settings settings = _randSettings();
            if (!isRegistered) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.KeyDoesNotExist.selector);
            } else if (_testKeyIsSignerAccount(testKey)) {
                revertData = _wrapCallFailedRevertData(IKeyManagement.CannotUpdateRootKey.selector);
            }
            return _updateCall(keyHash, settings, revertData);
        } else {
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

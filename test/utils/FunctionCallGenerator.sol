// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {IMinimalDelegation} from "../../src/interfaces/IMinimalDelegation.sol";
import {IKeyManagement} from "../../src/interfaces/IKeyManagement.sol";
import {IERC7821} from "../../src/interfaces/IERC7821.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {Key, KeyLib, KeyType} from "../../src/libraries/KeyLib.sol";
import {Settings} from "../../src/libraries/SettingsLib.sol";
import {CallBuilder} from "./CallBuilder.sol";
import {ExecuteHandler} from "./ExecuteHandler.sol";
import {GhostStateTracker} from "./GhostStateTracker.sol";
import {HandlerCall, HandlerCallLib} from "./HandlerCallLib.sol";
import {IHandlerGhostCallbacks} from "./GhostStateTracker.sol";
import {Settings, SettingsLib} from "../../src/libraries/SettingsLib.sol";

/**
 * @title FunctionCallGenerator
 * @dev Helper contract to generate random function calls for MinimalDelegation invariant testing
 */
abstract contract FunctionCallGenerator is Test, ExecuteHandler, GhostStateTracker {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallBuilder for Call;
    using CallBuilder for Call[];
    using HandlerCallLib for HandlerCall;
    using HandlerCallLib for HandlerCall[];
    using TestKeyManager for TestKey;

    // The contract instance to generate calls for
    IMinimalDelegation public immutable signerAccount;

    // Function type constants for selection (equal weighting)
    uint256 public constant FUNCTION_REGISTER = 0;
    uint256 public constant FUNCTION_REVOKE = 1;
    uint256 public constant FUNCTION_UPDATE = 2;
    uint256 public constant TRANSFER_TOKEN = 3;
    uint256 public constant FUNCTION_COUNT = 4; // Total number of function types

    // Recursion control
    uint256 public constant MAX_DEPTH = 5;

    address private immutable _tokenA;
    address private immutable _tokenB;

    constructor(IMinimalDelegation _signerAccount, address tokenA, address tokenB) {
        signerAccount = _signerAccount;
        _tokenA = tokenA;
        _tokenB = tokenB;
    }

    function _randomTestKey() internal returns (TestKey memory newKey) {
        newKey = TestKeyManager.withSeed(KeyType.Secp256k1, vm.randomUint());
    }

    function _registerCall(TestKey memory newKey) internal virtual returns (HandlerCall memory) {
        return HandlerCallLib.initDefault().withCall(
            CallBuilder.initDefault().withTo(address(signerAccount)).withData(
                abi.encodeWithSelector(IKeyManagement.register.selector, newKey.toKey())
            )
        ).withCallback(abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_RegisterCallback.selector, newKey.toKey()));
    }

    function _revokeCall(bytes32 keyHash) internal virtual returns (HandlerCall memory) {
        return HandlerCallLib.initDefault().withCall(
            CallBuilder.initDefault().withTo(address(signerAccount)).withData(
                abi.encodeWithSelector(IKeyManagement.revoke.selector, keyHash)
            )
        ).withCallback(abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_RevokeCallback.selector, keyHash));
    }

    function _updateCall(bytes32 keyHash, Settings settings) internal virtual returns (HandlerCall memory) {
        return HandlerCallLib.initDefault().withCall(
            CallBuilder.initDefault().withTo(address(signerAccount)).withData(
                abi.encodeWithSelector(IKeyManagement.update.selector, keyHash, settings)
            )
        ).withCallback(abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_UpdateCallback.selector, keyHash));
    }

    function _tokenTransferCall(address token, address to, uint256 amount) internal virtual returns (HandlerCall memory) {
        return HandlerCallLib.initDefault().withCall(
            CallBuilder.initDefault().withTo(token).withData(abi.encodeWithSelector(ERC20.transfer.selector, to, amount))
        );
    }

    function _getRandomKeyHash(uint256 seed) internal view returns (bytes32) {
        if (_ghostKeyHashes.values().length == 0) {
            return bytes32(0);
        }
        return _ghostKeyHashes.values()[seed % _ghostKeyHashes.values().length];
    }

    function _getSettingsForKeyHash(bytes32 keyHash) internal virtual returns (Settings) {}

    // TODO: add transient tracking of ghost key hashes to avoid revoking a key that was already revoked in different recursion depths 

    /**
     * @notice Generate a random function call with equal weighting between function types
     * @param randomSeed Random seed for generation
     * @param depth Current recursion depth
     * @return A call object for the generated function
     */
    function generateRandomFunctionHandlerCall(uint256 randomSeed, uint256 depth) public returns (HandlerCall memory) {
        vm.assume(randomSeed < type(uint256).max);
        // Select function type with equal weighting
        uint256 functionType = _bound(randomSeed, 0, FUNCTION_COUNT - 1);

        // REGISTER
        if (functionType == FUNCTION_REGISTER || _ghostKeyHashes.values().length == 0) {
            TestKey memory newKey = _randomTestKey();
            if(newKey.toKeyHash() != bytes32(0)) {
                return _registerCall(newKey);
            }
        }
        // REVOKE
        else if (functionType == FUNCTION_REVOKE) {
            bytes32 keyHashToRevoke = _getRandomKeyHash(randomSeed);
            if (keyHashToRevoke != bytes32(0)) {
                return _revokeCall(keyHashToRevoke);
            }
        }
        // UPDATE
        else if (functionType == FUNCTION_UPDATE) {
            bytes32 keyHashToUpdate = _getRandomKeyHash(randomSeed);
            Settings settings = _getSettingsForKeyHash(keyHashToUpdate);
            if (keyHashToUpdate != bytes32(0)) {
                return _updateCall(keyHashToUpdate, settings);
            }
        }

        // If no matches above, recurse
        if (depth < MAX_DEPTH) {
            HandlerCall[] memory innerCalls = _generateRandomHandlerCalls(randomSeed + 1, depth + 1);

            return HandlerCallLib.initDefault().withCall(
                CallBuilder.initDefault().withTo(address(signerAccount)).withData(
                    abi.encodeWithSelector(IERC7821.execute.selector, BATCHED_CALL, abi.encode(innerCalls.toCalls()))
                )
            ).withCallback(
                abi.encodeWithSelector(IHandlerGhostCallbacks.ghost_ExecuteCallback.selector, innerCalls)
            );
        } else {
            // Transfer is default
            return _tokenTransferCall(_tokenA, vm.randomAddress(), 1);
        }
    }

    /**
     * @notice Generate an array of random function calls
     * @param seed Random seed for generation
     * @param depth Current recursion depth
     * @return An array of call objects
     */
    function _generateRandomHandlerCalls(uint256 seed, uint256 depth) internal returns (HandlerCall[] memory) {
        // How many calls to generate (more at lower depths)
        uint256 cnt = _bound(seed % 10, 1, MAX_DEPTH - depth + 1);

        HandlerCall[] memory handlerCalls = new HandlerCall[](cnt);
        for (uint256 i = 0; i < cnt; i++) {
            handlerCalls[i] = generateRandomFunctionHandlerCall(uint256(keccak256(abi.encode(seed, i))), depth);
        }

        return handlerCalls;
    }

    /// @notice Executes registered callbacks for handler calls
    function _processCallbacks(HandlerCall[] memory handlerCalls) internal {
        for (uint256 i = 0; i < handlerCalls.length; i++) {
            if (handlerCalls[i].callback.length > 0) {
                (bool success, bytes memory revertData) = address(this).call(handlerCalls[i].callback);
                if(!success) {
                    console2.log("revertData");
                    console2.logBytes(revertData);
                }
                assertEq(success, true);
            }
        }
    }
}

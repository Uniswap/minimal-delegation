// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {Call, CallLib} from "./libraries/CallLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {ERC1271} from "./ERC1271.sol";
import {IERC1271} from "./interfaces/IERC1271.sol";
import {EIP712} from "./EIP712.sol";
import {ERC7201} from "./ERC7201.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {NonceManager} from "./NonceManager.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {WrappedDataHash} from "./libraries/WrappedDataHash.sol";
import {ERC7914} from "./ERC7914.sol";
import {SignedBatchedCallLib, SignedBatchedCall} from "./libraries/SignedBatchedCallLib.sol";
import {BatchedCallLib, BatchedCall} from "./libraries/BatchedCallLib.sol";
import {KeyManagement} from "./KeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";
import {HooksLib} from "./libraries/HooksLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {Settings, SettingsLib} from "./libraries/SettingsLib.sol";
import {Static} from "./libraries/Static.sol";
import {ERC7821} from "./ERC7821.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {Multicall} from "./Multicall.sol";

contract MinimalDelegation is
    IMinimalDelegation,
    ERC7821,
    ERC1271,
    EIP712,
    ERC4337Account,
    Receiver,
    KeyManagement,
    NonceManager,
    ERC7914,
    ERC7201,
    Multicall
{
    using ModeDecoder for bytes32;
    using KeyLib for *;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using CallLib for Call[];
    using BatchedCallLib for BatchedCall;
    using SignedBatchedCallLib for SignedBatchedCall;
    using HooksLib for IHook;
    using SettingsLib for Settings;

    function execute(BatchedCall memory batchedCall) public payable {
        bytes32 keyHash = msg.sender.toKeyHash();
        if (!_isOwnerOrAdmin(keyHash)) revert Unauthorized();
        _dispatch(batchedCall, keyHash);
    }

    function execute(SignedBatchedCall memory signedBatchedCall, bytes memory wrappedSignature) public payable {
        _handleVerifySignature(signedBatchedCall, wrappedSignature);
        _dispatch(signedBatchedCall.batchedCall, signedBatchedCall.keyHash);
    }

    function execute(bytes32 mode, bytes memory executionData) external payable override {
        if (!mode.isBatchedCall()) revert IERC7821.UnsupportedExecutionMode();
        Call[] memory calls = abi.decode(executionData, (Call[]));
        BatchedCall memory batchedCall = BatchedCall({calls: calls, shouldRevert: mode.shouldRevert()});
        execute(batchedCall);
    }

    /// @dev This function is executeable only by the EntryPoint contract, and is the main pathway for UserOperations to be executed.
    /// UserOperations can be executed through the execute function, but another method of authorization (ie through a passed in signature) is required.
    /// userOp.callData is abi.encodeCall(IAccountExecute.executeUserOp.selector, (abi.encode(Call[]), bool))
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint {
        // Parse the keyHash from the signature. This is the keyHash that has been pre-validated as the correct signer over the UserOp data
        // and must be used to check further on-chain permissions over the call execution.
        (bytes32 keyHash,,) = abi.decode(userOp.signature, (bytes32, bytes, bytes));

        // The mode is only passed in to signify the EXEC_TYPE of the calls.
        bytes calldata executionData = userOp.callData.removeSelector();
        (BatchedCall memory batchedCall) = abi.decode(executionData, (BatchedCall));

        _dispatch(batchedCall, keyHash);
    }

    function _dispatch(BatchedCall memory batchedCall, bytes32 keyHash) private {
        for (uint256 i = 0; i < batchedCall.calls.length; i++) {
            (bool success, bytes memory output) = _execute(batchedCall.calls[i], keyHash);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && batchedCall.shouldRevert) revert IMinimalDelegation.CallFailed(output);
        }
    }

    /// @dev Executes a low level call using execution hooks if set
    function _execute(Call memory _call, bytes32 keyHash) internal returns (bool success, bytes memory output) {
        // Per ERC7821, replace address(0) with address(this)
        address to = _call.to == address(0) ? address(this) : _call.to;

        Settings settings = getKeySettings(keyHash);
        if (!settings.isAdmin() && to == address(this)) revert IKeyManagement.OnlyAdminCanSelfCall();

        IHook hook = settings.hook();
        bytes memory beforeExecuteData;
        if (hook.hasPermission(HooksLib.BEFORE_EXECUTE_FLAG)) {
            beforeExecuteData = hook.handleBeforeExecute(keyHash, to, _call.value, _call.data);
        }

        (success, output) = to.call{value: _call.value}(_call.data);

        if (hook.hasPermission(HooksLib.AFTER_EXECUTE_FLAG)) hook.handleAfterExecute(keyHash, beforeExecuteData);
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        _payEntryPoint(missingAccountFunds);
        (bytes32 keyHash, bytes memory signature, bytes memory hookData) =
            abi.decode(userOp.signature, (bytes32, bytes, bytes));

        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions
        Key memory key = getKey(keyHash);
        bool isValid = key.verify(userOpHash, signature);

        // If signature verification failed, return failure immediately WITHOUT expiry as it cannot be trusted
        if (!isValid) {
            return SIG_VALIDATION_FAILED;
        }

        Settings settings = getKeySettings(keyHash);
        _checkExpiry(settings);

        /// validationData is (uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)
        /// `validAfter` is always 0.
        validationData = uint256(settings.expiration()) << 160 | SIG_VALIDATION_SUCCEEDED;

        IHook hook = settings.hook();
        if (hook.hasPermission(HooksLib.AFTER_VALIDATE_USER_OP_FLAG)) {
            // The hook can override the validation data
            validationData = hook.handleAfterValidateUserOp(keyHash, userOp, userOpHash, hookData);
        }
    }

    /// @dev This function is used to handle the verification of signatures sent through execute()
    function _handleVerifySignature(SignedBatchedCall memory signedBatchedCall, bytes memory wrappedSignature)
        private
    {
        _useNonce(signedBatchedCall.nonce);

        (bytes memory signature, bytes memory hookData) = abi.decode(wrappedSignature, (bytes, bytes));

        bytes32 digest = _hashTypedData(signedBatchedCall.hash());

        Key memory key = getKey(signedBatchedCall.keyHash);
        bool isValid = key.verify(digest, signature);
        if (!isValid) revert IMinimalDelegation.InvalidSignature();

        Settings settings = getKeySettings(signedBatchedCall.keyHash);
        _checkExpiry(settings);

        IHook hook = settings.hook();
        if (hook.hasPermission(HooksLib.AFTER_VERIFY_SIGNATURE_FLAG)) {
            // Hook must revert to signal that signature verification
            hook.handleAfterVerifySignature(signedBatchedCall.keyHash, digest, hookData);
        }
    }

    /// @notice Reverts if the key settings are expired
    function _checkExpiry(Settings settings) private view {
        (bool isExpired, uint40 expiry) = settings.isExpired();
        if (isExpired) revert IKeyManagement.KeyExpired(expiry);
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata wrappedSignature)
        public
        view
        override(ERC1271, IERC1271)
        returns (bytes4 result)
    {
        (bytes32 keyHash, bytes memory signature, bytes memory hookData) =
            abi.decode(wrappedSignature, (bytes32, bytes, bytes));
        bytes32 digest = _hashTypedData(data.hashWithWrappedType());

        Key memory key = getKey(keyHash);
        bool isValid = key.verify(digest, signature);
        if (!isValid) return _1271_INVALID_VALUE;
        result = _1271_MAGIC_VALUE;

        Settings settings = getKeySettings(keyHash);
        _checkExpiry(settings);

        IHook hook = settings.hook();
        if (hook.hasPermission(HooksLib.AFTER_IS_VALID_SIGNATURE_FLAG)) {
            // Hook can override the result
            result = hook.handleAfterIsValidSignature(keyHash, digest, hookData);
        }
    }
}

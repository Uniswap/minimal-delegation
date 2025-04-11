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
import {SignedCallsLib, SignedCalls} from "./libraries/SignedCallsLib.sol";
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
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using CallLib for Call[];
    using SignedCallsLib for SignedCalls;
    using HooksLib for IHook;
    using SettingsLib for Settings;

    function execute(Call[] memory calls, bool shouldRevert) public payable onlyThis {
        _dispatch(shouldRevert, calls, KeyLib.ROOT_KEY_HASH);
    }

    function execute(SignedCalls memory signedCalls, bytes memory signature) public payable {
        _handleVerifySignature(signedCalls, signature);
        _dispatch(signedCalls.shouldRevert, signedCalls.calls, signedCalls.keyHash);
    }

    function execute(bytes32 mode, bytes memory executionData) external payable override {
        if (!mode.isBatchedCall()) revert IERC7821.UnsupportedExecutionMode();
        Call[] memory calls = abi.decode(executionData, (Call[]));
        execute(calls, mode.shouldRevert());
    }

    /// @dev This function is executeable only by the EntryPoint contract, and is the main pathway for UserOperations to be executed.
    /// UserOperations can be executed through the execute function, but another method of authorization (ie through a passed in signature) is required.
    /// userOp.callData is abi.encodeCall(IAccountExecute.executeUserOp.selector, (bytes32 mode, bytes executionData)) where executionData is abi.encode(Call[]).
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint {
        // Parse the keyHash from the signature. This is the keyHash that has been pre-validated as the correct signer over the UserOp data
        // and must be used to check further on-chain permissions over the call execution.

        (bytes32 keyHash,) = abi.decode(userOp.signature, (bytes32, bytes));

        // The mode is only passed in to signify the EXEC_TYPE of the calls.
        bytes calldata executionData = userOp.callData.removeSelector();
        (Call[] memory calls, bool shouldRevert) = abi.decode(executionData, (Call[], bool));

        _dispatch(shouldRevert, calls, keyHash);
    }

    function _dispatch(bool shouldRevert, Call[] memory calls, bytes32 keyHash) private {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory output) = _execute(calls[i], keyHash);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && shouldRevert) revert IMinimalDelegation.CallFailed(output);
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
        (bytes32 keyHash, bytes memory signature) = abi.decode(userOp.signature, (bytes32, bytes));

        Settings settings = getKeySettings(keyHash);
        (bool isExpired, uint40 expiry) = settings.isExpired();
        if (isExpired) revert IKeyManagement.KeyExpired(expiry);

        IHook hook = settings.hook();
        validationData = hook.hasPermission(HooksLib.VALIDATE_USER_OP_FLAG)
            ? hook.validateUserOp(keyHash, userOp, userOpHash)
            : _handleValidateUserOp(keyHash, signature, userOp, userOpHash, expiry);
    }

    function _handleValidateUserOp(
        bytes32 keyHash,
        bytes memory signature,
        PackedUserOperation memory,
        bytes32 userOpHash,
        uint40 expiry
    ) private view returns (uint256 validationData) {
        Key memory key = getKey(keyHash);
        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions

        /// validationData is (uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)
        /// `validAfter` is always 0.
        if (key.verify(userOpHash, signature)) return uint256(expiry) << 160 | SIG_VALIDATION_SUCCEEDED;
        else return uint256(expiry) << 160 | SIG_VALIDATION_FAILED;
    }

    /// @dev This function is used to handle the verification of signatures sent through execute()
    function _handleVerifySignature(SignedCalls memory signedCalls, bytes memory signature) private {
        _useNonce(signedCalls.nonce);

        Key memory key = getKey(signedCalls.keyHash);
        Settings settings = getKeySettings(signedCalls.keyHash);
        (bool isExpired, uint40 expiry) = settings.isExpired();
        if (isExpired) revert IKeyManagement.KeyExpired(expiry);

        IHook hook = settings.hook();

        bytes32 digest = _hashTypedData(signedCalls.hash());

        bool isValid = hook.hasPermission(HooksLib.VERIFY_SIGNATURE_FLAG)
            ? hook.verifySignature(signedCalls.keyHash, digest, signature)
            : key.verify(digest, signature);

        if (!isValid) revert IMinimalDelegation.InvalidSignature();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata wrappedSignature)
        public
        view
        override(ERC1271, IERC1271)
        returns (bytes4 result)
    {
        (bytes32 keyHash, bytes memory signature) = abi.decode(wrappedSignature, (bytes32, bytes));

        Settings settings = getKeySettings(keyHash);
        (bool isExpired, uint40 expiry) = settings.isExpired();
        if (isExpired) revert IKeyManagement.KeyExpired(expiry);

        IHook hook = settings.hook();
        result = hook.hasPermission(HooksLib.IS_VALID_SIGNATURE_FLAG)
            ? hook.isValidSignature(keyHash, data, signature)
            : _handleIsValidSignature(keyHash, data, signature);
    }

    function _handleIsValidSignature(bytes32 keyHash, bytes32 data, bytes memory signature)
        private
        view
        returns (bytes4 result)
    {
        Key memory key = getKey(keyHash);
        if (key.verify(_hashTypedData(data.hashWithWrappedType()), signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID_VALUE;
    }
}

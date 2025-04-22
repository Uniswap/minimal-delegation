// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "./interfaces/IERC1271.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {IHook} from "./interfaces/IHook.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {EIP712} from "./EIP712.sol";
import {ERC1271} from "./ERC1271.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {ERC7201} from "./ERC7201.sol";
import {ERC7821} from "./ERC7821.sol";
import {ERC7914} from "./ERC7914.sol";
import {ERC7739} from "./ERC7739.sol";
import {KeyManagement} from "./KeyManagement.sol";
import {Multicall} from "./Multicall.sol";
import {NonceManager} from "./NonceManager.sol";
import {BatchedCallLib, BatchedCall} from "./libraries/BatchedCallLib.sol";
import {Call, CallLib} from "./libraries/CallLib.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {ERC7739Utils} from "./libraries/ERC7739Utils.sol";
import {HooksLib} from "./libraries/HooksLib.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {Settings, SettingsLib} from "./libraries/SettingsLib.sol";
import {SignedBatchedCallLib, SignedBatchedCall} from "./libraries/SignedBatchedCallLib.sol";
import {Static} from "./libraries/Static.sol";

contract MinimalDelegation is
    IMinimalDelegation,
    ERC7821,
    ERC1271,
    ERC4337Account,
    Receiver,
    KeyManagement,
    NonceManager,
    ERC7914,
    ERC7201,
    ERC7739,
    EIP712,
    Multicall
{
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call[];
    using BatchedCallLib for BatchedCall;
    using SignedBatchedCallLib for SignedBatchedCall;
    using KeyLib for *;
    using ModeDecoder for bytes32;
    using CalldataDecoder for bytes;
    using HooksLib for IHook;
    using SettingsLib for Settings;
    using ERC7739Utils for bytes;

    /// @inheritdoc IMinimalDelegation
    function execute(BatchedCall memory batchedCall) public payable {
        bytes32 keyHash = msg.sender.toKeyHash();
        if (!_isOwnerOrAdmin(keyHash)) revert Unauthorized();
        _processBatch(batchedCall, keyHash);
    }

    /// @inheritdoc IMinimalDelegation
    function execute(SignedBatchedCall memory signedBatchedCall, bytes memory wrappedSignature) public payable {
        if (!_senderIsExecutor(signedBatchedCall.executor)) revert Unauthorized();
        _handleVerifySignature(signedBatchedCall, wrappedSignature);
        _processBatch(signedBatchedCall.batchedCall, signedBatchedCall.keyHash);
    }

    /// @inheritdoc IERC7821
    function execute(bytes32 mode, bytes memory executionData) external payable override {
        if (!mode.isBatchedCall()) revert IERC7821.UnsupportedExecutionMode();
        Call[] memory calls = abi.decode(executionData, (Call[]));
        BatchedCall memory batchedCall = BatchedCall({calls: calls, revertOnFailure: mode.revertOnFailure()});
        execute(batchedCall);
    }

    /// @dev This function is executeable only by the EntryPoint contract, and is the main pathway for UserOperations to be executed.
    /// UserOperations can be executed through the execute function, but another method of authorization (ie through a passed in signature) is required.
    /// userOp.callData is abi.encodeCall(IAccountExecute.executeUserOp.selector, (abi.encode(Call[]), bool))
    /// Note that this contract is only compatible with Entrypoint versions v0.7.0 and v0.8.0. It is not compatible with v0.6.0, as that version does not support the "executeUserOp" selector.
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint {
        // Parse the keyHash from the signature. This is the keyHash that has been pre-validated as the correct signer over the UserOp data
        // and must be used to check further on-chain permissions over the call execution.
        (bytes32 keyHash,,) = abi.decode(userOp.signature, (bytes32, bytes, bytes));

        // The mode is only passed in to signify the EXEC_TYPE of the calls.
        bytes calldata executionData = userOp.callData.removeSelector();
        (BatchedCall memory batchedCall) = abi.decode(executionData, (BatchedCall));

        _processBatch(batchedCall, keyHash);
    }

    /// @inheritdoc IAccount
    /// @dev Only return validationData if the signature from the key associated with `keyHash` is valid over the userOpHash
    ///      - The ERC-4337 spec requires that `validateUserOp` does not early return if the signature is invalid such that accurate gas estimation can be done
    /// @return validationData is (uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (isValid ? 0 : 1)
    /// - `validAfter` is always 0.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        _payEntryPoint(missingAccountFunds);
        (bytes32 keyHash, bytes memory signature, bytes memory hookData) =
            abi.decode(userOp.signature, (bytes32, bytes, bytes));

        /// The userOpHash does not need to be made replay-safe, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        Key memory key = getKey(keyHash);
        bool isValid = key.verify(userOpHash, signature);

        Settings settings = getKeySettings(keyHash);
        settings.hook().handleAfterValidateUserOp(keyHash, userOp, userOpHash, hookData);

        /// validationData is (uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)
        /// `validAfter` is always 0.
        validationData =
            isValid ? uint256(settings.expiration()) << 160 | SIG_VALIDATION_SUCCEEDED : SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc ERC1271
    /// @dev wrappedSignature contains a keyHash, signature, and any optional hook data
    ///      `signature` can contain extra fields used for webauthn verification or ERC7739 nested typed data verification
    function isValidSignature(bytes32 digest, bytes calldata wrappedSignature)
        public
        view
        override(ERC1271, IERC1271)
        returns (bytes4)
    {
        // Per ERC-7739, return 0x77390001 for the sentinel hash value
        unchecked {
            if (wrappedSignature.length == uint256(0)) {
                // Forces the compiler to optimize for smaller bytecode size.
                if (uint256(digest) == ~wrappedSignature.length / 0xffff * 0x7739) return 0x77390001;
            }
        }

        (bytes32 keyHash, bytes memory signature, bytes memory hookData) =
            abi.decode(wrappedSignature, (bytes32, bytes, bytes));

        Key memory key = getKey(keyHash);

        /// There are 3 ways to validate a signature through ERC-1271:
        /// 1. The caller is allowlisted, so we can validate the signature directly against the data.
        /// 2. The caller is address(0), meaning it is an offchain call, so we can validate the signature as if it is a PersonalSign.
        /// 3. If none of the above is true, the signature must be validated as a TypedDataSign struct according to ERC-7739.
        bool isValid;
        if (erc1271CallerIsSafe[msg.sender]) {
            isValid = key.verify(digest, signature);
        } else if (msg.sender == address(0)) {
            // We only support PersonalSign for offchain calls
            isValid = _isValidNestedPersonalSig(key, digest, domainSeparator(), signature);
        } else {
            isValid = _isValidTypedDataSig(key, digest, domainBytes(), signature);
        }

        // Early return if the signature is invalid
        if (!isValid) return _1271_INVALID_VALUE;

        Settings settings = getKeySettings(keyHash);
        _checkExpiry(settings);

        settings.hook().handleAfterIsValidSignature(keyHash, digest, hookData);

        return _1271_MAGIC_VALUE;
    }

    /// @dev Iterates through calls, reverting according to specified failure mode
    function _processBatch(BatchedCall memory batchedCall, bytes32 keyHash) private {
        for (uint256 i = 0; i < batchedCall.calls.length; i++) {
            (bool success, bytes memory output) = _process(batchedCall.calls[i], keyHash);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && batchedCall.revertOnFailure) revert IMinimalDelegation.CallFailed(output);
        }
    }

    /// @dev Executes a low level call using execution hooks if set
    function _process(Call memory _call, bytes32 keyHash) private returns (bool success, bytes memory output) {
        // Per ERC7821, replace address(0) with address(this)
        address to = _call.to == address(0) ? address(this) : _call.to;

        Settings settings = getKeySettings(keyHash);
        if (!settings.isAdmin() && to == address(this)) revert IKeyManagement.OnlyAdminCanSelfCall();

        IHook hook = settings.hook();
        bytes memory beforeExecuteData = hook.handleBeforeExecute(keyHash, to, _call.value, _call.data);

        (success, output) = to.call{value: _call.value}(_call.data);

        hook.handleAfterExecute(keyHash, beforeExecuteData);
    }

    /// @dev This function is used to handle the verification of signatures sent through execute()
    function _handleVerifySignature(SignedBatchedCall memory signedBatchedCall, bytes memory wrappedSignature)
        private
    {
        _useNonce(signedBatchedCall.nonce);

        (bytes memory signature, bytes memory hookData) = abi.decode(wrappedSignature, (bytes, bytes));

        bytes32 digest = hashTypedData(signedBatchedCall.hash());

        Key memory key = getKey(signedBatchedCall.keyHash);
        bool isValid = key.verify(digest, signature);
        if (!isValid) revert IMinimalDelegation.InvalidSignature();

        Settings settings = getKeySettings(signedBatchedCall.keyHash);
        _checkExpiry(settings);

        settings.hook().handleAfterVerifySignature(signedBatchedCall.keyHash, digest, hookData);
    }

    /// @notice Returns true if the msg.sender is the executor or if the executor is address(0)
    /// @param executor The address of the allowed executor of the signed batched call
    function _senderIsExecutor(address executor) private view returns (bool) {
        return executor == address(0) || executor == msg.sender;
    }
}

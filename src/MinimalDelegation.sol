// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {Call, CallLib} from "./libraries/CallLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {ERC1271} from "./ERC1271.sol";
import {EIP712} from "./EIP712.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {NonceManager} from "./NonceManager.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {WrappedDataHash} from "./libraries/WrappedDataHash.sol";
import {ExecutionDataLib, ExecutionData} from "./libraries/ExecuteLib.sol";
import {KeyManagement} from "./KeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";
import {SignatureUnwrapper} from "./libraries/SignatureUnwrapper.sol";
import {HooksLib} from "./libraries/HooksLib.sol";
import {Settings, SettingsLib} from "./libraries/SettingsLib.sol";
import {Static} from "./libraries/Static.sol";
import {EntrypointLib} from "./libraries/EntrypointLib.sol";

contract MinimalDelegation is IERC7821, ERC1271, EIP712, ERC4337Account, Receiver, KeyManagement, NonceManager {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using ExecutionDataLib for ExecutionData;
    using SignatureUnwrapper for bytes;
    using HooksLib for IHook;
    using SettingsLib for Settings;
    using EntrypointLib for uint256;

    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        if (mode.isBatchedCall()) {
            Call[] calldata calls = executionData.decodeCalls();
            _onlyThis();
            _dispatch(mode, calls);
        } else if (mode.supportsOpData()) {
            // executionData.decodeWithOpData();
            (Call[] calldata calls, bytes calldata opData) = executionData.decodeCallsBytes();
            _authorizeOpData(mode, calls, opData);
            _dispatch(mode, calls);
        } else {
            revert IERC7821.UnsupportedExecutionMode();
        }
    }

    /// @dev This function is executeable only by the EntryPoint contract, and is the main pathway for UserOperations to be executed.
    /// UserOperations can be executed through the execute function, but another method of authorization (ie through a passed in signature) is required.
    /// userOp.callData is abi.encodeCall(IAccountExecute.executeUserOp.selector, (bytes32 mode, bytes executionData)) where executionData is abi.encode(Call[]).
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint {
        // Parse the keyHash from the signature. This is the keyHash that has been pre-validated as the correct signer over the UserOp data
        // and must be used to check further on-chain permissions over the call execution.
        // TODO: Handle keyHash authorization.
        // (bytes32 keyHash,) = userOp.signature.unwrap();

        // The mode is only passed in to signify the EXEC_TYPE of the calls.
        (bytes32 mode, bytes calldata executionData) = userOp.callData.removeSelector().decodeBytes32Bytes();
        if (!mode.isBatchedCall()) revert IERC7821.UnsupportedExecutionMode();
        Call[] calldata calls = executionData.decodeCalls();

        _dispatch(mode, calls);
    }

    /// @dev The mode is passed to allow other modes to specify different types of opData decoding.
    function _authorizeOpData(bytes32, Call[] calldata calls, bytes calldata opData) private {
        (uint256 nonce, bytes calldata wrappedSignature) = opData.decodeUint256Bytes();
        _useNonce(nonce);
        ExecutionData memory executionData = ExecutionData({calls: calls, nonce: nonce});

        (bytes32 keyHash, bytes calldata signature) = wrappedSignature.unwrap();
        Key memory key = _getKey(keyHash);

        IHook hook = MinimalDelegationStorageLib.get().keySettings[keyHash].hook();

        /// TODO: Handle key expiry check.
        bytes32 digest = _hashTypedData(executionData.hash());

        bool isValid = hook.hasPermission(HooksLib.VERIFY_SIGNATURE_FLAG)
            ? hook.overrideVerifySignature(keyHash, digest, signature)
            : key.verify(digest, signature);

        if (!isValid) revert IERC7821.InvalidSignature();
    }

    /// @dev Dispatches a batch of calls.
    function _dispatch(bytes32 mode, Call[] calldata calls) private {
        bool shouldRevert = mode.shouldRevert();

        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory output) = _execute(calls[i]);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && shouldRevert) revert IERC7821.CallFailed(output);
        }
    }

    // Execute a single call.
    function _execute(Call calldata _call) private returns (bool success, bytes memory output) {
        address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall() || mode.supportsOpData();
    }

    /// @inheritdoc IERC4337Account
    function updateEntryPoint(address entryPoint) external {
        _onlyThis();
        MinimalDelegationStorageLib.get().entryPoint = EntrypointLib.pack(entryPoint);
        emit EntryPointUpdated(entryPoint);
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        uint256 packedEntryPoint = MinimalDelegationStorageLib.get().entryPoint;
        return packedEntryPoint.isOverriden() ? packedEntryPoint.unpack() : Static.ENTRY_POINT_V_0_8;
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        _payEntryPoint(missingAccountFunds);
        (bytes32 keyHash, bytes calldata signature) = userOp.signature.unwrap();

        IHook hook = MinimalDelegationStorageLib.get().keySettings[keyHash].hook();

        /// TODO: Handle key expiry check.
        validationData = hook.hasPermission(HooksLib.VALIDATE_USER_OP_FLAG)
            ? hook.validateUserOp(keyHash, userOp, userOpHash)
            : _handleValidateUserOp(keyHash, signature, userOp, userOpHash);
    }

    /// TODO: This is left as an internal function to handle wrapping the returned validation data accoring to ERC-4337 spec.
    function _handleValidateUserOp(
        bytes32 keyHash,
        bytes calldata signature,
        PackedUserOperation calldata,
        bytes32 userOpHash
    ) private view returns (uint256 validationData) {
        Key memory key = _getKey(keyHash);
        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions
        if (key.verify(userOpHash, signature)) return SIG_VALIDATION_SUCCEEDED;
        else return SIG_VALIDATION_FAILED;
    }

    function _onlyThis() internal view override(KeyManagement, NonceManager) {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata wrappedSignature)
        public
        view
        override
        returns (bytes4 result)
    {
        (bytes32 keyHash, bytes calldata signature) = wrappedSignature.unwrap();

        IHook hook = MinimalDelegationStorageLib.get().keySettings[keyHash].hook();

        result = hook.hasPermission(HooksLib.IS_VALID_SIGNATURE_FLAG)
            ? hook.isValidSignature(keyHash, data, signature)
            : _handleIsValidSignature(keyHash, data, signature);
    }

    function _handleIsValidSignature(bytes32 keyHash, bytes32 data, bytes calldata signature)
        private
        view
        returns (bytes4 result)
    {
        Key memory key = _getKey(keyHash);
        if (key.verify(_hashTypedData(data.hashWithWrappedType()), signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID_VALUE;
    }
}

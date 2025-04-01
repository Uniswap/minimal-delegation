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
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {WrappedDataHash} from "./libraries/WrappedDataHash.sol";
import {ExecutionDataLib, ExecutionData} from "./libraries/ExecuteLib.sol";
import {KeyManagement} from "./KeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";
import {SignatureUnwrapper} from "./libraries/SignatureUnwrapper.sol";
import {HookId, HookFlags, HookLib} from "./libraries/HookLib.sol";

contract MinimalDelegation is IERC7821, IKeyManagement, ERC1271, EIP712, ERC4337Account, Receiver, KeyManagement {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call[];
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using ExecutionDataLib for ExecutionData;
    using SignatureUnwrapper for bytes;
    using HookLib for uint256;

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

    /// @dev The mode is passed to allow other modes to specify different types of opData decoding.
    function _authorizeOpData(bytes32, Call[] calldata calls, bytes calldata opData) private view {
        if (msg.sender == ENTRY_POINT()) {
            // TODO: check nonce and parse out key hash from opData if desired to usein future
            // short circuit because entrypoint is already verified using validateUserOp
            return;
        }

        // TODO: Can switch on mode to handle different types of authorization, or decoding of opData.
        (, bytes calldata wrappedSignature) = opData.decodeUint256Bytes();
        // TODO: Decode as an execute struct with the nonce. This is temporary!
        ExecutionData memory executeStruct = ExecutionData({calls: calls});

        (bytes32 keyHash, bytes calldata signature) = wrappedSignature.unwrap();
        IHook validator = HookLib.get(keyHash, HookFlags.VERIFY_SIGNATURE);

        bool isValid;
        if (address(validator) != address(0)) {
            isValid = validator.verifySignature(_hashTypedData(executeStruct.hash()), wrappedSignature);
        } else {
            // Use default signature verification.
            isValid = _verifySignature(_hashTypedData(executeStruct.hash()), keyHash, signature);
        }

        if (!isValid) revert IERC7821.InvalidSignature();
    }

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall() || mode.supportsOpData();
    }

    /// @inheritdoc IERC4337Account
    function updateEntryPoint(address entryPoint) external {
        _onlyThis();
        MinimalDelegationStorageLib.get().entryPoint = entryPoint;
        emit EntryPointUpdated(entryPoint);
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        _payEntryPoint(missingAccountFunds);
        (bytes32 keyHash, bytes calldata signature) = userOp.signature.unwrap();

        IHook validator = HookLib.get(keyHash, HookFlags.VALIDATE_USER_OP);
        if (address(validator) != address(0)) {
            return validator.validateUserOp(userOp, userOpHash);
        }
        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions
        if (_verifySignature(userOpHash, keyHash, signature)) return SIG_VALIDATION_SUCCEEDED;
        else return SIG_VALIDATION_FAILED;
    }

    function _onlyThis() internal view override {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata signature) public view override returns (bytes4 result) {
        (bytes32 keyHash, bytes calldata _signature) = signature.unwrap();

        IHook validator = HookLib.get(keyHash, HookFlags.VALIDATE_USER_OP);
        if (address(validator) != address(0)) {
            return validator.isValidSignature(data, signature);
        }

        /// TODO: Hashing it with the wrapped type obfuscates the data underneath if it is typed. We may not want to do this!
        if (_verifySignature(_hashTypedData(data.hashWithWrappedType()), keyHash, _signature)) return _1271_MAGIC_VALUE;
        return _1271_INVALID_VALUE;
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        return MinimalDelegationStorageLib.get().entryPoint;
    }

    /// @notice Sets a validator for a key
    function setValidator(bytes32 keyHash, HookId id) external {
        _onlyThis();
        HookLib.set(keyHash, id);
    }

    /// @notice Verifies that the key signed over the digest
    /// Handles signatures from the root ECDSA key and wrapped signatures
    function _verifySignature(bytes32 digest, bytes32 keyHash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        if (keyHash == bytes32(0)) {
            // Recover to the root EOA key
            isValid = ECDSA.recoverCalldata(digest, signature) == address(this);
        } else {
            Key memory key = _getKey(keyHash);
            isValid = key.verify(digest, signature);
        }
    }
}

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
import {BaseExecutor} from "./BaseExecutor.sol";
import {BaseValidator} from "./BaseValidator.sol";
import {ValidationModuleManager} from "./ValidationModuleManager.sol";
import {IValidator} from "./interfaces/IValidator.sol";

contract MinimalDelegation is
    IERC7821,
    IKeyManagement,
    ERC1271,
    EIP712,
    ERC4337Account,
    Receiver,
    KeyManagement,
    BaseExecutor,
    BaseValidator,
    ValidationModuleManager
{
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call[];
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using ExecutionDataLib for ExecutionData;

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
        // Check signature.
        if (!_unwrapAndVerifySignature(_hashTypedData(executeStruct.hash()), wrappedSignature)) {
            revert IERC7821.InvalidSignature();
        }
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
        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions
        if (_unwrapAndVerifySignature(userOpHash, userOp.signature)) return SIG_VALIDATION_SUCCEEDED;
        else return SIG_VALIDATION_FAILED;
    }

    function _onlyThis() internal view override {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata signature) public view override returns (bytes4 result) {
        /// TODO: Hashing it with the wrapped type obfuscates the data underneath if it is typed. We may not want to do this!
        if (_unwrapAndVerifySignature(_hashTypedData(data.hashWithWrappedType()), signature)) return _1271_MAGIC_VALUE;
        return _1271_INVALID_VALUE;
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        return MinimalDelegationStorageLib.get().entryPoint;
    }

    function setValidator(bytes32 keyHash, IValidator validator) external {
        _onlyThis();
        _setValidator(keyHash, validator);
    }

    /// @notice Verifies that the key signed over the digest
    /// Handles signatures from the root ECDSA key and wrapped signatures
    /// @dev If the key has a validator, it will use that validator to verify the signature instead of the fallback implementation
    function _unwrapAndVerifySignature(bytes32 digest, bytes calldata signatureOrWrapped)
        internal
        view
        returns (bool isValid)
    {
        if (_isRawSignature(signatureOrWrapped)) {
            isValid = _verifySignature(digest, signatureOrWrapped);
        } else {
            (bytes32 keyHash, bytes calldata signature) = CalldataDecoder.decodeBytes32Bytes(signatureOrWrapped);
            IValidator validator = _getValidator(keyHash);
            if (address(validator) != address(0)) {
                // pass the wrapped signature to the validator, containing the keyHash and signature
                return validator.verifySignature(digest, signatureOrWrapped);
            }

            Key memory key = _getKey(keyHash);
            return _verifySignature(digest, key, signature);
        }
    }
}

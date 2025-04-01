// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {Call} from "./libraries/CallLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {ERC1271} from "./ERC1271.sol";
import {EIP712} from "./EIP712.sol";
import {CallLib} from "./libraries/CallLib.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {WrappedDataHash} from "./libraries/WrappedDataHash.sol";
import {ExecutionDataLib, ExecutionData} from "./libraries/ExecuteLib.sol";
import {KeyManagement} from "./KeyManagement.sol";

contract MinimalDelegation is IERC7821, ERC1271, EIP712, ERC4337Account, KeyManagement, Receiver {
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
            _authorizeCaller();
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
        (, bytes calldata signature) = opData.decodeUint256Bytes();
        // TODO: Decode as an execute struct with the nonce. This is temporary!
        ExecutionData memory executeStruct = ExecutionData({calls: calls});
        // Check signature.
        bool isValid;
        (isValid,) = _isValidSignature(_hashTypedData(executeStruct.hash()), signature);
        if (!isValid) revert IERC7821.InvalidSignature();
    }

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
        _authorizeCaller();
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
        (bool isValid,) = _isValidSignature(userOpHash, userOp.signature);
        if (isValid) return SIG_VALIDATION_SUCCEEDED;
        else return SIG_VALIDATION_FAILED;
    }

    function _authorizeCaller() internal view override {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata signature) public view override returns (bytes4 result) {
        /// TODO: Hashing it with the wrapped type obfuscates the data underneath if it is typed. We may not want to do this!
        (bool isValid,) = _isValidSignature(_hashTypedData(data.hashWithWrappedType()), signature);
        if (isValid) return _1271_MAGIC_VALUE;
        return _1271_INVALID_VALUE;
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        return MinimalDelegationStorageLib.get().entryPoint;
    }

    function _isValidSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        returns (bool isValid, bytes32 keyHash)
    {
        if (_signature.length == 64 || _signature.length == 65) {
            // The signature is not wrapped, so it can be verified against the root key.
            isValid = ECDSA.recoverCalldata(_hash, _signature) == address(this);
        } else {
            // The signature is wrapped.
            bytes memory signature;
            (keyHash, signature) = abi.decode(_signature, (bytes32, bytes));
            Key memory key = _getKey(keyHash);
            isValid = key.verify(_hash, signature);
        }
    }
}

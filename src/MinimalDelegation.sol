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
import {Lock} from "./Lock.sol";

contract MinimalDelegation is IERC7821, IKeyManagement, ERC1271, EIP712, ERC4337Account, Lock, Receiver {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call[];
    using CalldataDecoder for bytes;

    /// @notice Public view function to be used instead of msg.sender, as the contract performs self-reentrancy and at
    /// times msg.sender == address(this). Instead msgSender() returns the initiator of the lock
    function msgSender() public view returns (address) {
        return _getLocker();
    }

    function execute(bytes32 mode, bytes calldata executionData) external payable override isNotLocked {
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
        // TODO: Can switch on mode to handle different types of authorization, or decoding of opData.
        // For now, we only support decoding necessary information needed to verify 1271 signatures.
        (, bytes calldata signature) = opData.decodeUint256Bytes();
        // TODO: Nonce validation.
        // Check signature.
        bool isValid;
        /// The calls are not safe hashed with _hashTypedData, as the domain separator is sufficient to prevent against replay attacks.
        (isValid,) = _isValidSignature(calls.hash(), signature);
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

    /// @inheritdoc IKeyManagement
    function authorize(Key memory key) external isNotLocked returns (bytes32 keyHash) {
        _authorizeCaller();
        keyHash = _authorize(key);
        emit Authorized(keyHash, key);
    }

    /// @inheritdoc IKeyManagement
    function revoke(bytes32 keyHash) external isNotLocked {
        _authorizeCaller();
        _revoke(keyHash);
        emit Revoked(keyHash);
    }

    /// @inheritdoc IKeyManagement
    function keyCount() external view returns (uint256) {
        return MinimalDelegationStorageLib.get().keyHashes.length();
    }

    /// @inheritdoc IKeyManagement
    function keyAt(uint256 i) external view returns (Key memory) {
        return _getKey(MinimalDelegationStorageLib.get().keyHashes.at(i));
    }

    /// @inheritdoc IKeyManagement
    function getKey(bytes32 keyHash) external view returns (Key memory) {
        return _getKey(keyHash);
    }

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall() || mode.supportsOpData();
    }

    /// @inheritdoc IERC4337Account
    function updateEntryPoint(address entryPoint) external isNotLocked {
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

    function _authorizeCaller() private view {
        if (msgSender() != address(this)) revert IERC7821.Unauthorized();
    }

    // Execute a batch of calls according to the mode
    function _authorize(Key memory key) private returns (bytes32 keyHash) {
        keyHash = key.hash();
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        // If the keyHash already exists, it does not revert and updates the key instead.
        minimalDelegationStorage.keyStorage[keyHash] = abi.encode(key);
        minimalDelegationStorage.keyHashes.add(keyHash);
    }

    function _revoke(bytes32 keyHash) private {
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        delete minimalDelegationStorage.keyStorage[keyHash];
        if (!minimalDelegationStorage.keyHashes.remove(keyHash)) {
            revert KeyDoesNotExist();
        }
    }

    function _getKey(bytes32 keyHash) private view returns (Key memory) {
        bytes memory data = MinimalDelegationStorageLib.get().keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4 result) {
        (bool isValid,) = _isValidSignature(_hashTypedData(hash), signature);
        if (isValid) return _1271_MAGIC_VALUE;
        return _1271_INVALID_VALUE;
    }

    // Execute a batch of calls according to the mode and any optionally provided opData
    function _execute(bytes32, Call[] memory, bytes memory) private pure {
        // TODO: unpack anything required from opData
        // verify signature from within opData
        // if signature is valid, execute the calls
        revert("Not implemented");
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

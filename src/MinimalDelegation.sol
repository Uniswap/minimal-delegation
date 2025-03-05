// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {Call, CallLib} from "./libraries/CallLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {CalldataLib} from "./libraries/CalldataLib.sol";
import {ERC1271} from "./ERC1271.sol";
import {EIP712} from "./EIP712.sol";
import {Executor} from "./Executor.sol";

contract MinimalDelegation is IERC7821, IKeyManagement, ERC1271, EIP712, Executor {
    using CallLib for Call[];
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CalldataLib for bytes;

    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4 result) {
        if (_isValidSignature({hash: _hashTypedData(hash), signature: signature})) {
            return _1271_MAGIC_VALUE;
        }

        return _1271_INVALID_VALUE;
    }

    /// @inheritdoc IERC7821
    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        if (!mode.isSupported()) revert IERC7821.UnsupportedExecutionMode();

        (Call[] calldata calls, bytes calldata opData) = executionData.parseExecutionData();
        _execute(mode, calls, opData);
    }

    function setCanExecute(bytes32 keyHash, address target, bool can) public {
        _authorizeCaller();
        _setCanExecute(keyHash, target, can);
    }

    /// @inheritdoc IKeyManagement
    function authorize(Key memory key) external returns (bytes32 keyHash) {
        _authorizeCaller();
        keyHash = _authorize(key);
        emit Authorized(keyHash, key);
    }

    /// @inheritdoc IKeyManagement
    function revoke(bytes32 keyHash) external {
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

    /// @inheritdoc IERC7821
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isSupported();
    }

    function _authorizeCaller() private view {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
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

    // Execute a batch of calls according to the mode and any optionally provided opData
    function _execute(bytes32 mode, Call[] memory calls, bytes calldata opData) private {
        // The caller must be address(this) if the mode is batchedCall
        if (mode.isBatchedCall()) {
            _authorizeCaller();
            return _execute(mode, calls, EOA_KEYHASH);
        }

        // Decode the opData
        // ex. check the nonce

        // Finally ensure the signature is valid and decode the keyHash
        (bool isValid, bytes32 keyHash) = _unwrapAndValidateSignature(calls.hash(), opData);
        if (!isValid) revert IERC7821.Unauthorized();

        return _execute(mode, calls, keyHash);
    }

    /// @dev Keyhash logic not implemented yet for 1271
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view override returns (bool) {
        (bool isValid,) = _unwrapAndValidateSignature(hash, signature);
        return isValid;
    }

    /// @dev Returns if the signature is valid, along with its `keyHash`.
    /// @dev If signed with the root private key the keyHash is 0.
    function _unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool isValid, bytes32 keyHash)
    {
        // If the signature's length is 64 or 65, treat it like an secp256k1 signature.
        if (signature.length == 64 || signature.length == 65) {
            return (ECDSA.recoverCalldata(digest, signature) == address(this), 0);
        }
        // not implemented
        revert("Not implemented");
    }
}

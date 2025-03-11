// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
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

contract MinimalDelegation is IERC7821, IKeyManagement, ERC1271, EIP712 {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call[];
    using CalldataDecoder for bytes;

    error NotImplemented();

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
        // TODO: Can switch on mode to handle different types of authorization, or decoding of opData.
        // For now, we only support decoding necessary information needed to verify 1271 signatures.
        (, bytes calldata signature) = opData.decodeUint256Bytes();
        // TODO: Nonce validation.
        // Check signature.
        bool isValid;
        (isValid,) = _unwrapAndValidateSignature(_hashTypedData(calls.hash()), signature);
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

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall() || mode.supportsOpData();
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

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4 result) {
        if (_isValidSignature({hash: _hashTypedData(hash), signature: signature})) {
            return _1271_MAGIC_VALUE;
        }

        return _1271_INVALID_VALUE;
    }

    // Execute a batch of calls according to the mode and any optionally provided opData
    function _execute(bytes32, Call[] memory, bytes memory) private pure {
        // TODO: unpack anything required from opData
        // verify signature from within opData
        // if signature is valid, execute the calls
        revert("Not implemented");
    }

    /// @dev Keyhash logic not implemented yet
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view override returns (bool isValid) {
        // If the signature's length is 64 or 65, treat it like an secp256k1 signature.
        if (signature.length == 64 || signature.length == 65) {
            return ECDSA.recoverCalldata(hash, signature) == address(this);
        }
        // Otherwise, treat the signature as a wrapped signature, and unwrap it before validating.
        (isValid,) = _unwrapAndValidateSignature(hash, signature);
    }

    /// @dev Returns if the wrapped signature is valid.
    /// TODO: Implement WebAuthnP256 validation.
    function _unwrapAndValidateSignature(bytes32 digest, bytes calldata wrappedSignature)
        internal
        view
        returns (bool isValid, Key memory key)
    {
        (bytes32 keyHash, bytes memory signature) = abi.decode(wrappedSignature, (bytes32, bytes));
        key = _getKey(keyHash);

        if (key.keyType == KeyType.P256) {
            // Extract x,y from the public key
            (bytes32 x, bytes32 y) = abi.decode(key.publicKey, (bytes32, bytes32));
            // Split signature into r and s values.
            (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
            isValid = P256.verify(digest, r, s, x, y);
        } else {
            isValid = false;
        }
    }
}

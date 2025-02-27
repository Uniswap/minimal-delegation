// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IERC7821, Calls} from "./interfaces/IERC7821.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {ERC1271} from "./ERC1271.sol";

contract MinimalDelegation is IERC7821, IKeyManagement, ERC1271 {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        if (mode.isBatchedCall()) {
            Calls[] memory calls = abi.decode(executionData, (Calls[]));
            _authorizeCaller();
            _execute(mode, calls);
        } else if (mode.supportsOpData()) {
            (Calls[] memory calls, bytes memory opData) = abi.decode(executionData, (Calls[], bytes));
            _execute(mode, calls, opData);
        } else {
            revert IERC7821.UnsupportedExecutionMode();
        }
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

    // Execute a batch of calls according to the mode and any optionally provided opData
    function _execute(bytes32 mode, Calls[] memory calls, bytes memory opData) private {
        // TODO: unpack anything required from opData
        // verify signature from within opData
        // if signature is valid, execute the calls
        revert("Not implemented");
    }

    // We currently only support calls initiated by the contract itself which means there are no checks needed on the target contract.
    // In the future, other keys can make calls according to their key permissions and those checks will need to be added.
    function _execute(bytes32 mode, Calls[] memory calls) private {
        bool shouldRevert = mode.shouldRevert();
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory output) = _execute(calls[i]);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && shouldRevert) revert IERC7821.CallFailed(output);
        }
    }

    // Execute a single call
    function _execute(Calls memory _call) private returns (bool success, bytes memory output) {
        address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        return ("Uniswap Minimal Delegation", "1");
    }

    /// @dev Keyhash logic not implemented yet
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view override returns (bool) {
        (bool isValid,) = _unwrapAndValidateSignature(hash, signature);
        return isValid;
    }

    /// @dev Returns if the signature is valid, along with its `keyHash`.
    function _unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool isValid, bytes32 keyHash)
    {
        // If the signature's length is 64 or 65, treat it like an secp256k1 signature.
        if (signature.length == 64 || signature.length == 65) {
            // keyHash for the root private key is 0
            return (ECDSA.recoverCalldata(digest, signature) == address(this), 0);
        }
        // not implemented
        revert("Not implemented");
    }
}

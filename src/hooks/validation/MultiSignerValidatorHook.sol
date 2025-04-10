// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Key, KeyLib} from "../../libraries/KeyLib.sol";
import {Call, CallLib} from "../../libraries/CallLib.sol";
import {IValidationHook} from "../../interfaces/IValidationHook.sol";
import {AccountKeyHash, AccountKeyHashLib} from "../shared/AccountKeyHashLib.sol";

/// @notice A transient storage library for hook data
/// TODO: This library can be deleted when we have the transient keyword support in solidity.
library HookDataTransientStorage {
    function _computeSlot(AccountKeyHash keyHash) internal pure returns (bytes32 hashSlot) {
        assembly ("memory-safe") {
            // mask the keyHash to 32 bytes
            mstore(0, and(keyHash, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
            hashSlot := keccak256(0, 32)
        }
    }

    function get(AccountKeyHash keyHash) internal view returns (bytes memory hookData) {
        bytes32 hashSlot = _computeSlot(keyHash);
        assembly ("memory-safe") {
            hookData := tload(hashSlot)
        }
    }

    function set(AccountKeyHash keyHash, bytes memory hookData) internal {
        bytes32 hashSlot = _computeSlot(keyHash);
        assembly ("memory-safe") {
            tstore(hashSlot, hookData)
        }
    }
}

/// @title MultiSignerValidatorHook
/// Require signatures from additional, arbitary signers for a key
contract MultiSignerValidatorHook is IValidationHook {
    using HookDataTransientStorage for AccountKeyHash;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call;
    using CallLib for Call[];
    using AccountKeyHashLib for bytes32;

    mapping(AccountKeyHash => EnumerableSetLib.Bytes32Set requiredSigners) private requiredSigners;
    mapping(bytes32 => bytes encodedKey) private keyStorage;

    error InvalidSignature();
    error InvalidSignatureCount();
    error SignerNotRegistered();

    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

    event RequiredSignerAdded(bytes32 keyHash, bytes32 signerKeyHash);

    /// @notice Add a required signer for a call.
    /// @dev Calculates the accountKeyHash using the msg.sender and the provided keyHash
    function addRequiredSigner(bytes32 keyHash, bytes calldata encodedKey) external {
        Key memory signerKey = abi.decode(encodedKey, (Key));
        bytes32 signerKeyHash = signerKey.hash();

        keyStorage[signerKeyHash] = encodedKey;
        requiredSigners[keyHash.wrap(msg.sender)].add(signerKeyHash);

        emit RequiredSignerAdded(keyHash, signerKeyHash);
    }

    /// @notice Set the hook data transiently for a key
    /// @dev Must be called by the expected sender of the hook calls
    /// This is used to store the required signers for a key
    function setHookData(bytes32 keyHash, bytes calldata hookData) external {
        AccountKeyHash accountKeyHash = keyHash.wrap(msg.sender);
        accountKeyHash.set(hookData);
    }

    /// @inheritdoc IValidationHook
    function afterValidateUserOp(bytes32 keyHash, PackedUserOperation calldata, bytes32 userOpHash)
        external
        view
        returns (bytes4 selector, uint256 validationData)
    {
        return (IValidationHook.afterValidateUserOp.selector, _hasAllRequiredSignatures(keyHash, userOpHash) ? 0 : 1);
    }

    /// @inheritdoc IValidationHook
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest)
        external
        view
        returns (bytes4 selector, bytes4 magicValue)
    {
        return (
            IValidationHook.afterIsValidSignature.selector,
            _hasAllRequiredSignatures(keyHash, digest) ? _1271_MAGIC_VALUE : _1271_INVALID_VALUE
        );
    }

    /// @inheritdoc IValidationHook
    function afterVerifySignature(bytes32 keyHash, bytes32 digest) external view returns (bytes4 selector) {
        if (!_hasAllRequiredSignatures(keyHash, digest)) revert InvalidSignature();
        return IValidationHook.afterVerifySignature.selector;
    }

    /// @notice Check if all required signers have signed over the digest
    /// @dev verifies `hookData` is an array of wrapped signer signatures matching the requiredSigners for the keyHash
    function _hasAllRequiredSignatures(bytes32 keyHash, bytes32 digest) internal view returns (bool isValid) {
        AccountKeyHash accountKeyHash = keyHash.wrap(msg.sender);
        bytes memory hookData = accountKeyHash.get();
        (bytes[] memory wrappedSignerSignatures) = abi.decode(hookData, (bytes[]));
        if (wrappedSignerSignatures.length != requiredSigners[accountKeyHash].length()) revert InvalidSignatureCount();

        // iterate over requiredSigners
        for (uint256 i = 0; i < requiredSigners[accountKeyHash].length(); i++) {
            (bytes32 signerKeyHash, bytes memory signerSignature) =
                abi.decode(wrappedSignerSignatures[i], (bytes32, bytes));

            if (!requiredSigners[accountKeyHash].contains(signerKeyHash)) revert SignerNotRegistered();

            Key memory signerKey = abi.decode(keyStorage[signerKeyHash], (Key));
            isValid = KeyLib.verify(signerKey, digest, signerSignature);

            // break if any signatures are invalid
            if (!isValid) {
                return false;
            }
        }

        return true;
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Key, KeyLib} from "../../libraries/KeyLib.sol";
import {Call, CallLib} from "../../libraries/CallLib.sol";
import {IValidationHook} from "../../interfaces/IValidationHook.sol";
import {AccountKeyHash, AccountKeyHashLib} from "../shared/AccountKeyHashLib.sol";

/// @title MultiSignerValidatorHook
/// Require signatures from additional, arbitary signers for a key
contract MultiSignerValidatorHook is IValidationHook {
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

    /// @inheritdoc IValidationHook
    function afterValidateUserOp(
        bytes32 keyHash,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata hookData
    ) external view returns (bytes4 selector, uint256 validationData) {
        return (
            IValidationHook.afterValidateUserOp.selector,
            _hasAllRequiredSignatures(keyHash, userOpHash, hookData) ? 0 : 1
        );
    }

    /// @inheritdoc IValidationHook
    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        external
        view
        returns (bytes4 selector, bytes4 magicValue)
    {
        (bytes[] memory wrappedSignerSignatures) = abi.decode(hookData, (bytes[]));
        return (
            IValidationHook.afterIsValidSignature.selector,
            _hasAllRequiredSignatures(keyHash, digest, hookData) ? _1271_MAGIC_VALUE : _1271_INVALID_VALUE
        );
    }

    /// @inheritdoc IValidationHook
    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        external
        view
        returns (bytes4 selector)
    {
        if (!_hasAllRequiredSignatures(keyHash, digest, hookData)) revert InvalidSignature();
        return IValidationHook.afterVerifySignature.selector;
    }

    /// @notice Check if all required signers have signed over the digest
    /// @dev verifies `hookData` is an array of wrapped signer signatures matching the requiredSigners for the keyHash
    function _hasAllRequiredSignatures(bytes32 keyHash, bytes32 digest, bytes calldata hookData)
        internal
        view
        returns (bool isValid)
    {
        (bytes[] memory wrappedSignerSignatures) = abi.decode(hookData, (bytes[]));
        AccountKeyHash accountKeyHash = keyHash.wrap(msg.sender);
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

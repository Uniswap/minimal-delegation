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
/// TODO: add threshold signature verification
contract MultiSignerValidatorHook is IValidationHook {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call;
    using CallLib for Call[];
    using AccountKeyHashLib for bytes32;

    mapping(AccountKeyHash => EnumerableSetLib.Bytes32Set requiredSigners) private requiredSigners;
    mapping(bytes32 => bytes encodedKey) private keyStorage;

    error InvalidSignatureCount();
    error MissingSigner();

    /// @notice Add a required signer for a call.
    /// @dev Calculates the accountKeyHash using the msg.sender and the provided keyHash
    function addRequiredSigner(bytes32 keyHash, bytes calldata encodedKey) external {
        Key memory signerKey = abi.decode(encodedKey, (Key));
        bytes32 signerKeyHash = signerKey.hash();

        keyStorage[signerKeyHash] = encodedKey;
        requiredSigners[keyHash.wrap(msg.sender)].add(signerKeyHash);
    }

    function afterValidateUserOp(bytes32 keyHash, PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata witness)
        external
        view
        returns (bytes4 selector, uint256 validationData)
    {
        // TODO:
        return (IValidationHook.afterValidateUserOp.selector, 0);
    }

    function afterIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata witness) 
        external 
        view 
        returns (bytes4 selector, bytes4 magicValue) 
    {
        // TODO:
        bytes4 _1271_MAGIC_VALUE = 0x1626ba7e;
        return (IValidationHook.afterIsValidSignature.selector, _1271_MAGIC_VALUE);
    }

    function afterVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata witness)
        external
        view
        returns (bytes4 selector)
    {
        (bytes[] memory wrappedSignerSignatures) = abi.decode(witness, (bytes[]));
        AccountKeyHash accountKeyHash = keyHash.wrap(msg.sender);

        if (wrappedSignerSignatures.length != requiredSigners[accountKeyHash].length()) revert InvalidSignatureCount();

        // iterate over requiredSigners
        for (uint256 i = 0; i < requiredSigners[accountKeyHash].length(); i++) {
            // Verify that keyHash is in the requiredSigners set
            (bytes32 signerKeyHash, bytes memory signerSignature) =
                abi.decode(wrappedSignerSignatures[i], (bytes32, bytes));

            if (!requiredSigners[accountKeyHash].contains(signerKeyHash)) revert MissingSigner();

            Key memory signerKey = abi.decode(keyStorage[signerKeyHash], (Key));
            bool isValid = KeyLib.verify(signerKey, digest, signerSignature);

            if (!isValid) {
                revert("Invalid additional signer signature");
            }
        }

        return IValidationHook.afterVerifySignature.selector;
    }
}

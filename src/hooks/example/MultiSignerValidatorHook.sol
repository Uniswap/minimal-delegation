// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Key, KeyLib} from "../../libraries/KeyLib.sol";
import {Call, CallLib} from "../../libraries/CallLib.sol";
import {IHook} from "../../interfaces/IHook.sol";

type AccountKeyHash is bytes32;

library MultiSignerWrappedSignatureLib {
    function unwrap(bytes calldata wrappedSignature)
        internal
        pure
        returns (bytes32 keyHash, bytes[] memory signatures)
    {
        (keyHash, signatures) = abi.decode(wrappedSignature, (bytes32, bytes[]));
    }
}

/// @title MultiSignerValidatorHook
/// Require signatures from additional, arbitary signers for a key
/// TODO: add threshold signature verification
contract MultiSignerValidatorHook is IHook {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call;
    using CallLib for Call[];
    using MultiSignerWrappedSignatureLib for bytes;

    mapping(AccountKeyHash => EnumerableSetLib.Bytes32Set requiredSigners) private requiredSigners;
    mapping(bytes32 => bytes encodedKey) private keyStorage;

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
        requiredSigners[_accountKeyHash(keyHash)].add(signerKeyHash);

        emit RequiredSignerAdded(keyHash, signerKeyHash);
    }

    function overrideValidateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        (bytes32 keyHash, bytes[] memory wrappedSignerSignatures) = userOp.signature.unwrap();
        // TODO: return correct validationData
        return _hasAllRequiredSignatures(keyHash, userOpHash, wrappedSignerSignatures) ? 0 : 1;
    }

    function overrideIsValidSignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData) external view returns (bytes4) {
        (bytes[] memory wrappedSignerSignatures) = hookData.unwrap();
        return _hasAllRequiredSignatures(keyHash, digest, wrappedSignerSignatures)
            ? _1271_MAGIC_VALUE
            : _1271_INVALID_VALUE;
    }

    function overrideVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata hookData) external view returns (bool isValid) {
        (bytes[] memory wrappedSignerSignatures) = hookData.unwrap();
        return _hasAllRequiredSignatures(keyHash, digest, wrappedSignerSignatures);
    }

    function _hasAllRequiredSignatures(bytes32 keyHash, bytes32 digest, bytes[] memory wrappedSignerSignatures)
        internal
        view
        returns (bool isValid)
    {
        AccountKeyHash accountKeyHash = _accountKeyHash(keyHash);
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
                return (IHook.overrideVerifySignature.selector, false);
            }
        }

        return (IHook.overrideVerifySignature.selector, true);
    }

    /// @notice Hash a call with the sender's account address
    function _accountKeyHash(bytes32 keyHash) internal view returns (AccountKeyHash) {
        return AccountKeyHash.wrap(keccak256(abi.encode(msg.sender, keyHash)));
    }
}

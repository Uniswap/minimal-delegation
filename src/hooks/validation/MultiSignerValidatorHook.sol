// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Key, KeyLib} from "../../libraries/KeyLib.sol";
import {Call, CallLib} from "../../libraries/CallLib.sol";
import {IHook} from "../../interfaces/IHook.sol";

type AccountKeyHash is bytes32;

/// @title MultiSignerValidatorHook
/// Require signatures from additional, arbitary signers for a key
/// TODO: add threshold signature verification
contract MultiSignerValidatorHook is IHook {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;
    using CallLib for Call;
    using CallLib for Call[];

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
        requiredSigners[_accountKeyHash(keyHash)].add(signerKeyHash);
    }

    function overrideValidateUserOp(bytes32, PackedUserOperation calldata, bytes32)
        external
        pure
        returns (bytes4, uint256)
    {
        revert("Not implemented");
    }

    function overrideIsValidSignature(bytes32, bytes32, bytes calldata) external pure returns (bytes4, bytes4) {
        revert("Not implemented");
    }

    function overrideVerifySignature(bytes32 keyHash, bytes32 digest, bytes calldata data)
        external
        view
        returns (bytes4, bool isValid)
    {
        (bytes[] memory wrappedSignerSignatures) = abi.decode(data, (bytes[]));
        AccountKeyHash accountKeyHash = _accountKeyHash(keyHash);

        if (wrappedSignerSignatures.length != requiredSigners[accountKeyHash].length()) revert InvalidSignatureCount();

        // iterate over requiredSigners
        for (uint256 i = 0; i < requiredSigners[accountKeyHash].length(); i++) {
            // Verify that keyHash is in the requiredSigners set
            (bytes32 signerKeyHash, bytes memory signerSignature) =
                abi.decode(wrappedSignerSignatures[i], (bytes32, bytes));

            if (!requiredSigners[accountKeyHash].contains(signerKeyHash)) revert MissingSigner();

            Key memory signerKey = abi.decode(keyStorage[signerKeyHash], (Key));
            isValid = KeyLib.verify(signerKey, digest, signerSignature);

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

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Call, CallLib} from "../../libraries/CallLib.sol";

type CallHash is bytes32;

type PackedCallSigner is bytes32;

interface ISignatureValidationCallback {
    function verifySignature(bytes32 callHash, bytes calldata wrappedSignature) external view returns (bool isValid);
}

/// TODO: add threshold signature verification
contract MultiSignerValidationVerifier {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CallLib for Call;
    using CallLib for Call[];

    mapping(CallHash => EnumerableSetLib.Bytes32Set requiredSigners) public requiredSigners;
    mapping(CallHash => mapping(bytes32 => bytes)) public cachedSignatures;

    error InvalidSignatureCount();
    error MissingSignature();

    /// @notice Initialize module data for the modular account.
    /// @dev Called by the modular account during `installExecution`.
    /// @param data Optional bytes array to be decoded and used by the module to setup initial module data for the
    /// modular account.
    function onInstall(bytes calldata data) external {
        (CallHash[] memory callHashes, bytes32[] memory keyHashes) = abi.decode(data, (CallHash[], bytes32[]));
        for (uint256 i = 0; i < callHashes.length; i++) {
            requiredSigners[callHashes[i]].add(keyHashes[i]);
        }
    }

    /// @notice Add a required signer for a call.
    /// @dev uses msg.sender
    function addRequiredSigner(Call calldata call, bytes32 keyHash) external {
        requiredSigners[_callHash(call)].add(keyHash);
    }

    /// @notice Cache a signature for a call.
    /// @dev uses msg.sender
    function cacheRuntimeValidationData(Call calldata call, bytes calldata data) external {
        CallHash callHash = _callHash(call);
        (bytes32 keyHash,) = abi.decode(data, (bytes32, bytes));
        cachedSignatures[callHash][keyHash] = data;
    }

    /**
     * PRE VALIDATION HOOKS
     */

    /// @notice Verify a call using transiently cached signatures.
    function preRuntimeValidationHook(Call calldata call, bytes calldata wrappedSignature)
        external
        view
        returns (bool isValid)
    {
        CallHash callHash = _callHash(call);

        // iterate over requiredSigners
        for (uint256 i = 0; i < requiredSigners[callHash].length(); i++) {
            bytes32 keyHash = requiredSigners[callHash].at(i);
            bytes memory cachedSignature = cachedSignatures[callHash][keyHash];
            if (cachedSignature.length == 0) revert MissingSignature();

            (isValid) = ISignatureValidationCallback(msg.sender).verifySignature(call.hash(), cachedSignature);
            if (!isValid) {
                return false;
            }
        }
    }

    /// @notice Hash a call with the sender's account address
    function _callHash(Call calldata call) internal view returns (CallHash) {
        return CallHash.wrap(keccak256(abi.encode(msg.sender, call.hash())));
    }
}

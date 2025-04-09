// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call, CallLib} from "../../src/libraries/CallLib.sol";
import {SignedCalls, SignedCallsLib} from "../../src/libraries/SignedCallsLib.sol";
import {KeyLib} from "../../src/libraries/KeyLib.sol";

/// @title SignedCallsBuilder
/// @notice A utility library for building SignedCalls objects in tests
library SignedCallsBuilder {
    using SignedCallsLib for SignedCalls;
    using CallLib for Call[];

    function initArray() internal pure returns (SignedCalls[] memory) {
        return new SignedCalls[](0);
    }

    function push(SignedCalls[] memory signedCalls, SignedCalls memory signedCall) internal pure returns (SignedCalls[] memory) {
        SignedCalls[] memory newSignedCalls = new SignedCalls[](signedCalls.length + 1);
        for (uint256 i = 0; i < signedCalls.length; i++) {
            newSignedCalls[i] = signedCalls[i];
        }
        newSignedCalls[signedCalls.length] = signedCall;
        return newSignedCalls;
    }

    /// @notice Initialize a SignedCalls object with default values
    /// @return A SignedCalls object with empty calls array, zero nonce, shouldRevert=false, empty keyHash and signature
    function init() internal pure returns (SignedCalls memory) {
        return SignedCalls({
            calls: new Call[](0),
            nonce: 0,
            shouldRevert: false,
            keyHash: bytes32(0),
            signature: bytes("")
        });
    }

    /// @notice Set the calls field of a SignedCalls object
    /// @param signedCalls The SignedCalls object to modify
    /// @param calls The new calls array
    /// @return The modified SignedCalls object
    function withCalls(SignedCalls memory signedCalls, Call[] memory calls) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        signedCalls.calls = calls;
        return signedCalls;
    }

    /// @notice Set the nonce field of a SignedCalls object
    /// @param signedCalls The SignedCalls object to modify
    /// @param nonce The new nonce
    /// @return The modified SignedCalls object
    function withNonce(SignedCalls memory signedCalls, uint256 nonce) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        signedCalls.nonce = nonce;
        return signedCalls;
    }

    /// @notice Set the shouldRevert field of a SignedCalls object
    /// @param signedCalls The SignedCalls object to modify
    /// @param shouldRevert Whether execution should revert if any call fails
    /// @return The modified SignedCalls object
    function withShouldRevert(SignedCalls memory signedCalls, bool shouldRevert) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        signedCalls.shouldRevert = shouldRevert;
        return signedCalls;
    }

    /// @notice Set the keyHash field of a SignedCalls object
    /// @param signedCalls The SignedCalls object to modify
    /// @param keyHash The hash of the key that will sign the transaction
    /// @return The modified SignedCalls object
    function withKeyHash(SignedCalls memory signedCalls, bytes32 keyHash) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        signedCalls.keyHash = keyHash;
        return signedCalls;
    }

    /// @notice Set the signature field of a SignedCalls object
    /// @param signedCalls The SignedCalls object to modify
    /// @param signature The signature data
    /// @return The modified SignedCalls object
    function withSignature(SignedCalls memory signedCalls, bytes memory signature) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        signedCalls.signature = signature;
        return signedCalls;
    }

    /// @notice Set the root signer key hash (bytes32(0))
    /// @param signedCalls The SignedCalls object to modify
    /// @return The modified SignedCalls object with the root key hash
    function withRootKeyHash(SignedCalls memory signedCalls)
        internal
        pure
        returns (SignedCalls memory)
    {
        signedCalls.keyHash = KeyLib.ROOT_KEY_HASH;
        return signedCalls;
    }

    /// @notice Convenience method to quickly create a SignedCalls object with calls and nonce
    /// @param calls The array of calls to execute
    /// @param nonce The nonce for replay protection
    /// @return A SignedCalls object with the specified calls and nonce, default values for other fields
    function from(Call[] memory calls, uint256 nonce) 
        internal 
        pure 
        returns (SignedCalls memory) 
    {
        return SignedCalls({
            calls: calls,
            nonce: nonce,
            shouldRevert: false,
            keyHash: bytes32(0),
            signature: bytes("")
        });
    }

    /// @notice Convenience method to calculate the hash of a SignedCalls object
    /// @param signedCalls The SignedCalls object to hash
    /// @return The EIP-712 compatible hash of the SignedCalls
    function hash(SignedCalls memory signedCalls) 
        internal 
        pure 
        returns (bytes32) 
    {
        return signedCalls.hash();
    }
}
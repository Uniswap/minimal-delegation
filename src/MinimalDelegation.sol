// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {Call, CallLib} from "./libraries/CallLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {ERC1271} from "./ERC1271.sol";
import {EIP712} from "./EIP712.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {NonceManager} from "./NonceManager.sol";
import {INonceManager} from "./interfaces/INonceManager.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {ERC4337Account} from "./ERC4337Account.sol";
import {IERC4337Account} from "./interfaces/IERC4337Account.sol";
import {WrappedDataHash} from "./libraries/WrappedDataHash.sol";
import {ExecutionDataLib, ExecutionData} from "./libraries/ExecuteLib.sol";
import {ERC7914} from "./ERC7914.sol";
import {KeyManagement} from "./KeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";
import {SignatureUnwrapper} from "./libraries/SignatureUnwrapper.sol";
import {HooksLib} from "./libraries/HooksLib.sol";

contract MinimalDelegation is
    IERC7821,
    ERC1271,
    EIP712,
    ERC4337Account,
    Receiver,
    KeyManagement,
    NonceManager,
    ERC7914
{
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using CalldataDecoder for bytes;
    using WrappedDataHash for bytes32;
    using ExecutionDataLib for ExecutionData;
    using SignatureUnwrapper for bytes;
    using HooksLib for IHook;

    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        if (mode.isBatchedCall()) {
            Call[] calldata calls = executionData.decodeCalls();
            _onlyThis();
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

    /// @dev This function is executeable only by the EntryPoint contract, and is the main pathway for UserOperations to be executed.
    /// UserOperations can be executed through the execute function, but another method of authorization (ie through a passed in signature) is required.
    /// userOp.callData is abi.encodeCall(IAccountExecute.executeUserOp.selector, (bytes32 mode, bytes executionData)) where executionData is abi.encode(Call[]).
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint {
        // Parse the keyHash from the signature. This is the keyHash that has been pre-validated as the correct signer over the UserOp data
        // and must be used to check further on-chain permissions over the call execution.
        // TODO: Handle keyHash authorization.
        // (bytes32 keyHash,) = userOp.signature.unwrap();

        // The mode is only passed in to signify the EXEC_TYPE of the calls.
        (bytes32 mode, bytes calldata executionData) = userOp.callData.removeSelector().decodeBytes32Bytes();
        if (!mode.isBatchedCall()) revert IERC7821.UnsupportedExecutionMode();
        Call[] calldata calls = executionData.decodeCalls();

        _dispatch(mode, calls);
    }

    /// @inheritdoc INonceManager
    function getNonce(uint256 key) public view override returns (uint256 nonce) {
        return MinimalDelegationStorageLib.get().nonceSequenceNumber[uint192(key)] | (key << 64);
    }

    /// @inheritdoc INonceManager
    function invalidateNonce(uint256 nonce) public override {
        _onlyThis();
        _invalidateNonce(nonce);
        emit NonceInvalidated(nonce);
    }

    /// @dev The mode is passed to allow other modes to specify different types of opData decoding.
    function _authorizeOpData(bytes32, Call[] calldata calls, bytes calldata opData) private {
        if (msg.sender == ENTRY_POINT()) {
            // TODO: check nonce and parse out key hash from opData if desired to usein future
            // short circuit because entrypoint is already verified using validateUserOp
            return;
        }

        // TODO: Can switch on mode to handle different types of authorization, or decoding of opData.
        (uint256 nonce, bytes calldata wrappedSignature) = opData.decodeUint256Bytes();
        _useNonce(nonce);
        ExecutionData memory executionData = ExecutionData({calls: calls, nonce: nonce});

        (bytes32 keyHash, bytes calldata signature) = wrappedSignature.unwrap();
        if (!_verifySignature(_hashTypedData(executionData.hash()), keyHash, signature)) {
            revert IERC7821.InvalidSignature();
        }
    }

    /// @dev Dispatches a batch of calls.
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

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall() || mode.supportsOpData();
    }

    /// @inheritdoc IERC4337Account
    function updateEntryPoint(address entryPoint) external {
        _onlyThis();
        MinimalDelegationStorageLib.get().entryPoint = entryPoint;
        emit EntryPointUpdated(entryPoint);
    }

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        _payEntryPoint(missingAccountFunds);
        (bytes32 keyHash, bytes calldata signature) = userOp.signature.unwrap();

        IHook hook = MinimalDelegationStorageLib.getKeyExtraStorage(keyHash).hook;
        if (hook.hasPermission(HooksLib.VALIDATE_USER_OP_FLAG)) {
            return hook.validateUserOp(userOp, userOpHash);
        }

        /// The userOpHash does not need to be safe hashed with _hashTypedData, as the EntryPoint will always call the sender contract of the UserOperation for validation.
        /// It is possible that the signature is a wrapped signature, so any supported key can be used to validate the signature.
        /// This is because the signature field is not defined by the protocol, but by the account implementation. See https://eips.ethereum.org/EIPS/eip-4337#definitions
        if (_verifySignature(userOpHash, keyHash, signature)) return SIG_VALIDATION_SUCCEEDED;
        else return SIG_VALIDATION_FAILED;
    }

    function _onlyThis() internal view override(KeyManagement, ERC7914) {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    /// @inheritdoc ERC1271
    function isValidSignature(bytes32 data, bytes calldata signature) public view override returns (bytes4 result) {
        (bytes32 keyHash, bytes calldata _signature) = signature.unwrap();

        IHook hook = MinimalDelegationStorageLib.getKeyExtraStorage(keyHash).hook;
        if (hook.hasPermission(HooksLib.IS_VALID_SIGNATURE_FLAG)) {
            return hook.isValidSignature(data, signature);
        }

        /// TODO: Hashing it with the wrapped type obfuscates the data underneath if it is typed. We may not want to do this!
        if (_verifySignature(_hashTypedData(data.hashWithWrappedType()), keyHash, _signature)) return _1271_MAGIC_VALUE;
        return _1271_INVALID_VALUE;
    }

    /// @inheritdoc IERC4337Account
    function ENTRY_POINT() public view override returns (address) {
        return MinimalDelegationStorageLib.get().entryPoint;
    }

    /// @notice Verifies that the key signed over the digest
    function _verifySignature(bytes32 digest, bytes32 keyHash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        Key memory key = _getKey(keyHash);
        isValid = key.verify(digest, signature);
    }
}

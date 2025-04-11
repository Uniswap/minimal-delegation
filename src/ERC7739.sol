// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC7739Utils} from "./libraries/ERC7739Utils.sol";
import {EIP712} from "./EIP712.sol";

/**
 * Implementing contracts MUST
 * - validate _callerHashMatchesReconstructedHash
 * - ensure contentsDescr is not empty
 */
abstract contract ERC7739 is EIP712 {
    using ERC7739Utils for *;
    using MessageHashUtils for bytes32;

    // TODO: natspec for all

    /**
     * @dev Uses this contract's domain separator which is calculated at runtime
     */
    function _getPersonalSignTypedDataHash(bytes32 hash) private view returns (bytes32) {
        return _domainSeparator().toTypedDataHash(hash.personalSignStructHash());
    }

    /// @dev the output MUST be hashed with the app's domain separator
    function _getNestedTypedDataSignHash(
        bytes32 appSeparator,
        string calldata contentsName,
        string calldata contentsType,
        bytes32 contentsHash
    ) private view returns (bytes32) {
        (string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt) =
            _eip712Domain();
        bytes memory domainBytes =
            abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
        return
            _hashTypedData(appSeparator, TypedDataSignLib.hash(contentsName, contentsType, contentsHash, domainBytes));
    }

    /// TODO: do in inheriting contract
    /// @dev the contentHash hashed with the app's separator MUST match the caller provided hash
    function _callerHashMatchesReconstructedHash(bytes32 appSeparator, bytes32 hash, bytes32 contentsHash)
        private
        view
        returns (bool)
    {
        return hash == _hashTypedData(appSeparator, contentsHash);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IEIP712} from "./interfaces/IEIP712.sol";

/// @title EIP712
/// @dev This contract does not cache the domain separator and calculates it on the fly since it will change when delegated to.
/// @notice It is not compatible with use by proxy contracts since the domain name and version are cached on deployment.
contract EIP712 is IEIP712, IERC5267 {
    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 internal constant _DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev Cached name and version hashes for cheaper runtime gas costs.
    bytes32 private immutable _cachedNameHash;
    bytes32 private immutable _cachedVersionHash;

    constructor() {
        string memory name;
        string memory version;
        (name, version) = _domainNameAndVersion();
        _cachedNameHash = keccak256(bytes(name));
        _cachedVersionHash = keccak256(bytes(version));
    }

    /// @notice Returns information about the `EIP712Domain` used to create EIP-712 compliant hashes.
    ///
    /// @dev Follows ERC-5267 (see https://eips.ethereum.org/EIPS/eip-5267).
    ///
    /// @return fields The bitmap of used fields.
    /// @return name The value of the `EIP712Domain.name` field.
    /// @return version The value of the `EIP712Domain.version` field.
    /// @return chainId The value of the `EIP712Domain.chainId` field.
    /// @return verifyingContract The value of the `EIP712Domain.verifyingContract` field.
    /// @return salt The value of the `EIP712Domain.salt` field.
    /// @return extensions The list of EIP numbers, that extends EIP-712 with new domain fields.
    function eip712Domain()
        external
        view
        virtual
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0f"; // `0b1111`.
        (name, version) = _domainNameAndVersion();
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt; // `bytes32(0)`.
        extensions = extensions; // `new uint256[](0)`.
    }

    /// @notice Returns the `domainSeparator` used to create EIP-712 compliant hashes.
    /// @return The 32 bytes domain separator result.
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(abi.encode(_DOMAIN_TYPEHASH, _cachedNameHash, _cachedVersionHash, block.chainid, address(this)));
    }

    /// @notice Public getter for `_hashTypedData()` to produce a replay-safe hash from the given `hash`.
    /// @param hash The nested typed data hash as defined by EIP-712. Assumes the hash is the result of applying EIP-712 hashStruct.
    /// @return The corresponding replay-safe hash.
    function hashTypedData(bytes32 hash) public view virtual returns (bytes32) {
        return _hashTypedData(hash);
    }

    /// @notice Returns the EIP-712 typed data hash
    /// @param hash The nested typed data hash as defined by EIP-712.  Assumes the hash is already compliant with EIP-712.
    /// @return The resulting EIP-712 hash.
    function _hashTypedData(bytes32 hash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), hash));
    }

    /// @notice Returns the domain name and version to use when creating EIP-712 signatures.
    /// @return name    The user readable name of signing domain.
    /// @return version The current major version of the signing domain.
    function _domainNameAndVersion() internal pure returns (string memory name, string memory version) {
        return ("Uniswap Minimal Delegation", "1");
    }
}

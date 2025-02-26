// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IERC1271
interface IERC1271 {
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    function domainSeparator() external view returns (bytes32);
    function replaySafeHash(bytes32 hash) external view returns (bytes32);
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

library InvariantRevertLib {
    using InvariantRevertLib for bytes[];

    function initArray() internal pure returns (bytes[] memory) {
        return new bytes[](0);
    }

    /// @dev Add a revert to an array
    function push(bytes[] memory self, bytes memory revertData) internal pure returns (bytes[] memory) {
        bytes[] memory newReverts = new bytes[](self.length + 1);
        for (uint256 i = 0; i < self.length; i++) {
            newReverts[i] = self[i];
        }
        newReverts[self.length] = revertData;
        return newReverts;
    }
}

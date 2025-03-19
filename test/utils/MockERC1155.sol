// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ERC1155} from "openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol";

/// @notice Mock ERC1155 contract for testing purposes.
contract MockERC1155 is ERC1155 {
    string public constant _uri = "https://uniswap.org/";

    constructor() ERC1155(_uri) {}

    function mint(address to, uint256 id, uint256 amount, bytes memory data) public {
        _mint(to, id, amount, data);
    }

    function burn(address from, uint256 id, uint256 amount) public {
        _burn(from, id, amount);
    }
}

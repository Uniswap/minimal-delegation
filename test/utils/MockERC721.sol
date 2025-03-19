// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";

/// @notice Mock ERC721 contract for testing purposes.
contract MockERC721 is ERC721 {
    string public constant _name = "MockERC721";
    string public constant _symbol = "M721";

    constructor() ERC721(_name, _symbol) {}

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
    }
}

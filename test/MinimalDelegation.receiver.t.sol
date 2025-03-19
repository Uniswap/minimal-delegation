// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {MockERC721} from "./utils/MockERC721.sol";
import {MockERC1155} from "./utils/MockERC1155.sol";

/// @notice Simple test for receiver functionality within MinimalDelegation.
/// @author https://github.com/Vectorized/solady/blob/main/test/Receiver.t.sol
contract MinimalDelegationReceiverTest is DelegationHandler {
    MockERC721 erc721;
    MockERC1155 erc1155;

    address alice = makeAddr("alice");

    function setUp() public {
        setUpDelegation();
        erc721 = new MockERC721();
        erc1155 = new MockERC1155();
    }

    function test_receive_eth() public {
        vm.deal(alice, 1e18);
        uint256 beforeBalance = address(signerAccount).balance;
        (bool success,) = address(signerAccount).call{value: 1e18}("");
        assertEq(success, true);
        assertEq(address(signerAccount).balance, beforeBalance + 1e18);
    }

    function test_receive_onERC721Received() public {
        erc721.mint(alice, 1);
        vm.prank(alice);
        erc721.safeTransferFrom(alice, address(signerAccount), 1);
        assertEq(erc721.balanceOf(address(signerAccount)), 1);
    }

    function test_receive_onERC1155Received() public {
        erc1155.mint(alice, 1, 1, "");
        vm.prank(alice);
        erc1155.safeTransferFrom(alice, address(signerAccount), 1, 1, "");
        assertEq(erc1155.balanceOf(address(signerAccount), 1), 1);
    }

    function test_receive_onERC1155BatchReceived() public {
        erc1155.mint(alice, 1, 1, "");
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amts = new uint256[](1);
        amts[0] = 1;
        vm.prank(alice);
        erc1155.safeBatchTransferFrom(alice, address(signerAccount), ids, amts, "");
        assertEq(erc1155.balanceOf(address(signerAccount), 1), 1);
    }
}

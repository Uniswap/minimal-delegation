// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {Call} from "../../src/libraries/CallLib.sol";

contract TokenHandler {
    ERC20Mock tokenA;
    ERC20Mock tokenB;

    function setUpTokens() public {
        tokenA = new ERC20Mock();
        tokenB = new ERC20Mock();
    }

    function buildTransferCall(address token, address to, uint256 amount) internal pure returns (Call memory call) {
        if (token == address(0)) {
            call.to = to;
            call.value = amount;
            call.data = "";
        } else {
            call.to = token;
            call.value = 0;
            call.data = abi.encodeWithSelector(ERC20.transfer.selector, to, amount);
        }
    }
}

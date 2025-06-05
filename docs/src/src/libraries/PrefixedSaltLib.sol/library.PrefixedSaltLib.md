# PrefixedSaltLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/PrefixedSaltLib.sol)

A library for packing and updating the salt with a prefix for EIP-712 domain separators


## Functions
### pack

Pack the prefix and implementation address into a bytes32


```solidity
function pack(uint96 prefix, address implementation) internal pure returns (bytes32);
```


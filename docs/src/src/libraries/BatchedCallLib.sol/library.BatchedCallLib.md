# BatchedCallLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/BatchedCallLib.sol)

Library for EIP-712 hashing of BatchedCall


## State Variables
### BATCHED_CALL_TYPE
*The type string for the BatchedCall struct*


```solidity
bytes internal constant BATCHED_CALL_TYPE =
    "BatchedCall(Call[] calls,bool revertOnFailure)Call(address to,uint256 value,bytes data)";
```


### BATCHED_CALL_TYPEHASH
*The typehash for the BatchedCall struct*


```solidity
bytes32 internal constant BATCHED_CALL_TYPEHASH = keccak256(BATCHED_CALL_TYPE);
```


## Functions
### hash


```solidity
function hash(BatchedCall memory batchedCall) internal pure returns (bytes32);
```


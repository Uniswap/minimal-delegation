# SignedBatchedCallLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/SignedBatchedCallLib.sol)

Library for EIP-712 hashing of SignedBatchedCall


## State Variables
### SIGNED_BATCHED_CALL_TYPE
*The type string for the SignedBatchedCall struct*


```solidity
bytes internal constant SIGNED_BATCHED_CALL_TYPE =
    "SignedBatchedCall(BatchedCall batchedCall,uint256 nonce,bytes32 keyHash,address executor,uint256 deadline)BatchedCall(Call[] calls,bool revertOnFailure)Call(address to,uint256 value,bytes data)";
```


### SIGNED_BATCHED_CALL_TYPEHASH
*The typehash for the SignedBatchedCall struct*


```solidity
bytes32 internal constant SIGNED_BATCHED_CALL_TYPEHASH = keccak256(SIGNED_BATCHED_CALL_TYPE);
```


## Functions
### hash

Hashes a SignedBatchedCall struct.


```solidity
function hash(SignedBatchedCall memory signedBatchedCall) internal pure returns (bytes32);
```


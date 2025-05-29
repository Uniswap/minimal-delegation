# SignedBatchedCallLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/libraries/SignedBatchedCallLib.sol)

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


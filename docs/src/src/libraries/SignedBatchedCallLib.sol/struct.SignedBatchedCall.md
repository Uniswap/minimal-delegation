# SignedBatchedCall
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/libraries/SignedBatchedCallLib.sol)


```solidity
struct SignedBatchedCall {
    BatchedCall batchedCall;
    uint256 nonce;
    bytes32 keyHash;
    address executor;
    uint256 deadline;
}
```


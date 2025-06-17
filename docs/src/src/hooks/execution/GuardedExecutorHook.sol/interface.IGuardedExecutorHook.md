# IGuardedExecutorHook
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/hooks/execution/GuardedExecutorHook.sol)

**Inherits:**
[IExecutionHook](/src/interfaces/IExecutionHook.sol/interface.IExecutionHook.md)


## Functions
### ANY_KEYHASH


```solidity
function ANY_KEYHASH() external view returns (bytes32);
```

### ANY_TARGET


```solidity
function ANY_TARGET() external view returns (address);
```

### ANY_FN_SEL


```solidity
function ANY_FN_SEL() external view returns (bytes4);
```

### setCanExecute


```solidity
function setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) external;
```

## Errors
### Unauthorized
Thrown when a key is not authorized to execute a call.


```solidity
error Unauthorized();
```

### SelfCallNotAllowed
Thrown when a self call is not allowed.


```solidity
error SelfCallNotAllowed();
```


# BaseAuthorization
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/BaseAuthorization.sol)

A base contract that provides a modifier to restrict access to the contract itself


## Functions
### onlyThis

A modifier that restricts access to the contract itself


```solidity
modifier onlyThis();
```

## Errors
### Unauthorized
An error that is thrown when an unauthorized address attempts to call a function


```solidity
error Unauthorized();
```


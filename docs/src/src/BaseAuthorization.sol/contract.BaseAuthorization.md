# BaseAuthorization
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/BaseAuthorization.sol)

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


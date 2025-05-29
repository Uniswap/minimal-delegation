# PersonalSignLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/libraries/PersonalSignLib.sol)

Library for hashing nested personal sign messages per ERC-7739


## State Variables
### PERSONAL_SIGN_TYPE

```solidity
bytes private constant PERSONAL_SIGN_TYPE = "PersonalSign(bytes prefixed)";
```


### PERSONAL_SIGN_TYPEHASH

```solidity
bytes32 private constant PERSONAL_SIGN_TYPEHASH = keccak256(PERSONAL_SIGN_TYPE);
```


## Functions
### hash

Calculate the hash of the PersonalSign type according to EIP-712

*This function is used within the context of ERC-1271 where we only have access to a bytes32 hash.
We assume that `message` is the hash of `prefixed`,
keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
such that it is compatible with how EIP-712 handles dynamic types
i.e. keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, keccak256(prefixed)))*


```solidity
function hash(bytes32 message) internal pure returns (bytes32);
```


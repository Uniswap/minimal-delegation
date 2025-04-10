# Minimal Delegation

a minimal, non-upgradeable implementation contract that can be set on an EIP-7702 delegation txn


## Features

- **ERC-4337**: Gas sponsorship and userOp handling through a 4337 interface.
- **ERC-7821**: Generic transaction batching through an ERC-7821 interface.
- **ERC-7201**: Name spaced storage to prevent collisions.
- **Key Management + Authorization** Adding & revoking keys that have access to perform operations as specified by the account owner.


## Architecture
- **Non-Upgradeability**: Upgradability is only allowed through re-delegation rather than a proxy.
- **Singleton:** One canonical contract is delegated to.

## Inheritance Diagram

```mermaid
classDiagram
    MinimalDelegation --|> ERC7821
    MinimalDelegation --|> ERC1271
    MinimalDelegation --|> EIP712
    MinimalDelegation --|> ERC4337Account
    MinimalDelegation --|> Receiver
    MinimalDelegation --|> KeyManagement
    MinimalDelegation --|> NonceManager
    MinimalDelegation --|> ERC7914
    MinimalDelegation --|> ERC7201
    
    EIP712 --|> IERC5267
    ERC4337Account --|> IAccount
    
    class MinimalDelegation {
        +execute(Call[] calls, bool shouldRevert)
        +execute(SignedCalls signedCalls, bytes signature)
        +execute(bytes32 mode, bytes executionData)
        +executeUserOp(PackedUserOperation userOp, bytes32)
        +updateEntryPoint(address entryPoint)
        +validateUserOp(PackedUserOperation userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    }
```
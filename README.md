# Minimal Delegation

a minimal, non-upgradeable implementation contract that can be set on an EIP-7702 delegation txn

## Installation
```bash
foundryup --install nightly

cd test/js-scripts && yarn && yarn build

forge test
```

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
        +execute(BatchedCall batchedCall)
        +execute(SignedBatchedCall signedBatchedCall, bytes signature)
        +execute(bytes32 mode, bytes executionData)
        +executeUserOp(PackedUserOperation userOp, bytes32)
        +updateEntryPoint(address entryPoint)
        +validateUserOp(PackedUserOperation userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    }
```

## Sequence Diagrams

### Direct execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to MinimalDelegation)
    participant Account as MinimalDelegation
    participant Target
    
    Note over SignerAccount, Account: EOA is delegated to MinimalDelegation via EIP-7702
    SignerAccount->>Account: execute(BatchedCall batchedCall)
    Account->>Account: _onlyThis()
    Account->>Account: _dispatch(batchedCall, ROOT_KEY_HASH)
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, ROOT_KEY_HASH)
        Account->>Account: getKeySettings(ROOT_KEY_HASH)
        Account->>Account: Check if admin for self-calls
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        opt If !success && batchedCall.shouldRevert
            Account->>Account: revert CallFailed(output)
        end
    end
```

### Signature-based execute() Flow

```mermaid
sequenceDiagram
    actor Signer
    participant Relayer
    participant Account as MinimalDelegation
    participant Hook
    participant Target
    
    Signer->>Signer: Create SignedBatchedCall structure
    Signer->>Signer: Sign the hash with private key
    Signer->>Relayer: Send signed transaction data
    Relayer->>+Account: execute(SignedBatchedCall, signature)
    Account->>Account: _handleVerifySignature(signedBatchedCall, signature)
    Account->>Account: _useNonce(signedBatchedCall.nonce)
    Account->>Account: getKey(signedBatchedCall.keyHash)
    Account->>Account: getKeySettings(signedBatchedCall.keyHash)
    Account->>Account: Check if key expired
    Account->>Account: _hashTypedData(signedBatchedCall.hash())
    
    alt Hook has VERIFY_SIGNATURE permission
        Account->>Hook: verifySignature(keyHash, digest, signature)
        Hook-->>Account: isValid
    else No hook or no permission
        Account->>Account: key.verify(digest, signature)
    end
    
    opt If !isValid
        Account-->>Relayer: revert InvalidSignature()
    end
    
    Account->>Account: _dispatch(signedBatchedCall.batchedCall, signedBatchedCall.keyHash)
    
    loop For each call in signedBatchedCall.batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && signedBatchedCall.batchedCall.shouldRevert
            Account-->>Relayer: revert CallFailed(output)
        end
    end
    
    Account-->>-Relayer: Success
```

### ERC7821 execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to MinimalDelegation)
    participant Account as MinimalDelegation
    participant Target
    
    Note over SignerAccount, Account: EOA is delegated to MinimalDelegation via EIP-7702
    SignerAccount->>Account: execute(bytes32 mode, bytes executionData)
    Account->>Account: mode.isBatchedCall()
    opt If !mode.isBatchedCall()
        Account-->>SignerAccount: revert UnsupportedExecutionMode()
    end
    
    Account->>Account: abi.decode(executionData) to Call[]
    Account->>Account: Create BatchedCall with calls and mode.shouldRevert()
    Account->>Account: execute(batchedCall)
    Account->>Account: _onlyThis()
    Account->>Account: _dispatch(batchedCall, ROOT_KEY_HASH)
    
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, ROOT_KEY_HASH)
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        opt If !success && batchedCall.shouldRevert
            Account-->>SignerAccount: revert CallFailed(output)
        end
    end
    
    Account-->>SignerAccount: Success
```

### ERC4337 UserOp Flow

```mermaid
sequenceDiagram
    actor Signer
    participant Bundler
    participant EntryPoint
    participant Account as MinimalDelegation
    participant Hook
    participant Target
    
    Signer->>Signer: Create UserOperation
    Signer->>Signer: Sign userOpHash
    Signer->>Bundler: Submit UserOperation
    
    Bundler->>+EntryPoint: handleOps([userOp], beneficiary)
    EntryPoint->>+Account: validateUserOp(userOp, userOpHash, missingAccountFunds)
    
    Account->>Account: _payEntryPoint(missingAccountFunds)
    Account->>Account: Decode signature to (keyHash, signature)
    Account->>Account: getKeySettings(keyHash)
    Account->>Account: Check if key expired
    
    alt Hook has VALIDATE_USER_OP permission
        Account->>Hook: validateUserOp(keyHash, userOp, userOpHash)
        Hook-->>Account: validationData
    else No hook or no permission
        Account->>Account: _handleValidateUserOp(keyHash, signature, userOp, userOpHash, expiry)
        Account->>Account: getKey(keyHash)
        Account->>Account: key.verify(userOpHash, signature)
        Account->>Account: Return validation result with expiry
    end
    
    Account-->>-EntryPoint: validationData
    
    EntryPoint->>+Account: executeUserOp(userOp, userOpHash)
    Account->>Account: Decode signature to extract keyHash
    Account->>Account: Decode callData to BatchedCall
    Account->>Account: _dispatch(batchedCall, keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.shouldRevert
            Account-->>EntryPoint: revert CallFailed(output)
        end
    end
    
    Account-->>-EntryPoint: Success
    EntryPoint-->>-Bundler: Success
```

### ERC1271 isValidSignature Flow

```mermaid
sequenceDiagram
    participant VerifyingContract
    participant Account as MinimalDelegation
    participant Hook
    
    VerifyingContract->>+Account: isValidSignature(bytes32 data, bytes wrappedSignature)
    
    Account->>Account: Decode wrappedSignature to (keyHash, signature)
    Account->>Account: getKeySettings(keyHash)
    Account->>Account: Check if key expired
    
    alt Hook has IS_VALID_SIGNATURE permission
        Account->>Hook: isValidSignature(keyHash, data, signature)
        Hook-->>Account: result
    else No hook or no permission
        Account->>Account: getKey(keyHash)
        Account->>Account: key.verify(_hashTypedData(data.hashWithWrappedType()), signature)
        Account->>Account: Return _1271_MAGIC_VALUE or _1271_INVALID_VALUE
    end
    
    Account-->>-VerifyingContract: result (0x1626ba7e if valid, otherwise 0xffffffff)
```

## Migration Notes

### Breaking Changes in v1.x.x

The contract has undergone a structural refactoring to improve modularization and separation of concerns:

1. **Structure Changes**:
   - `SignedCalls` has been replaced with two separate structures:
     - `BatchedCall`: Contains the call array and shouldRevert flag
     - `SignedBatchedCall`: Contains a BatchedCall, nonce, and keyHash

2. **Field Access Changes**:
   - Old: `signedCalls.calls` → New: `signedBatchedCall.batchedCall.calls`
   - Old: `signedCalls.shouldRevert` → New: `signedBatchedCall.batchedCall.shouldRevert`
   - Old: `signedCalls.nonce` → New: `signedBatchedCall.nonce` (unchanged)
   - Old: `signedCalls.keyHash` → New: `signedBatchedCall.keyHash` (unchanged)

3. **Type Hash Changes**:
   - EIP-712 type strings have been updated for the new structure
   - **IMPORTANT**: This changes the digest for signing, which affects offline signature generation

4. **Interface Updates**:
   - Function signatures updated to use the new structures
   - Old: `execute(Call[] calls, bool shouldRevert)` → New: `execute(BatchedCall batchedCall)`
   - Old: `execute(SignedCalls signedCalls, bytes signature)` → New: `execute(SignedBatchedCall signedBatchedCall, bytes signature)`

Integrators should update their code to accommodate these changes, particularly for signature generation and verification.
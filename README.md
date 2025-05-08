# Calibur

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
- **ERC-7739**: Defensive nested typed data hashing for improved security.
- **ERC-7914**: Native ETH approval and transfer functionality.
- **Key Management + Authorization** Adding & revoking keys that have access to perform operations as specified by the account owner.
- **Hooks System**: Extensible validation and execution hooks via bit-patterns.


## Architecture
- **Non-Upgradeability**: Upgradability is only allowed through re-delegation rather than a proxy.
- **Singleton:** One canonical contract is delegated to.

## Inheritance Diagram

```mermaid
classDiagram
    Calibur --|> ERC7821
    Calibur --|> ERC1271
    Calibur --|> EIP712
    Calibur --|> ERC4337Account
    Calibur --|> Receiver
    Calibur --|> KeyManagement
    Calibur --|> NonceManager
    Calibur --|> ERC7914
    Calibur --|> ERC7201
    Calibur --|> ERC7739
    Calibur --|> Multicall
    
    EIP712 --|> IERC5267
    ERC4337Account --|> IAccount
    
    class Calibur {
        +execute(BatchedCall batchedCall)
        +execute(SignedBatchedCall signedBatchedCall, bytes wrappedSignature)
        +execute(bytes32 mode, bytes executionData)
        +executeUserOp(PackedUserOperation userOp, bytes32)
        +validateUserOp(PackedUserOperation userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        +isValidSignature(bytes32 digest, bytes wrappedSignature)
    }
```

## Sequence Diagrams

### Direct execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to Calibur)
    participant Account as Calibur
    participant Hook
    participant Target
    
    Note over SignerAccount, Account: EOA is delegated to Calibur via EIP-7702
    SignerAccount->>Account: execute(BatchedCall batchedCall)
    Account->>Account: Check if sender keyHash is owner or admin
    Account->>Account: _processBatch(batchedCall, keyHash)
    loop For each call in batchedCall.calls
        Account->>Account: _process(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: beforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: afterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.revertOnFailure
            Account-->>SignerAccount: revert CallFailed(output)
        end
    end
```

### Signature-based execute() Flow

```mermaid
sequenceDiagram
    actor Signer
    participant Relayer
    participant Account as Calibur
    participant Hook
    participant Target
    
    Signer->>Signer: Create SignedBatchedCall structure
    Signer->>Signer: Sign the hash with private key
    Signer->>Relayer: Send signed transaction data
    Relayer->>+Account: execute(SignedBatchedCall, wrappedSignature)
    Account->>Account: Check if sender is executor
    Account->>Account: _handleVerifySignature(signedBatchedCall, wrappedSignature)
    Account->>Account: _useNonce(signedBatchedCall.nonce)
    Account->>Account: Decode wrappedSignature into (signature, hookData)
    Account->>Account: hashTypedData(signedBatchedCall.hash())
    Account->>Account: getKey(signedBatchedCall.keyHash)
    Account->>Account: key.verify(digest, signature)
    
    opt If !isValid
        Account-->>Relayer: revert InvalidSignature()
    end
    
    Account->>Account: getKeySettings(signedBatchedCall.keyHash)
    Account->>Account: _checkExpiry(settings)
    
    opt If hook has AFTER_VERIFY_SIGNATURE permission
        Account->>Hook: afterVerifySignature(keyHash, digest, hookData)
    end
    
    Account->>Account: _processBatch(signedBatchedCall.batchedCall, signedBatchedCall.keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _process(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: beforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: afterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.revertOnFailure
            Account-->>Relayer: revert CallFailed(output)
        end
    end
    
    Account-->>-Relayer: Success
```

### ERC7821 execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to Calibur)
    participant Account as Calibur
    participant Hook
    participant Target
    
    Note over SignerAccount, Account: EOA is delegated to Calibur via EIP-7702
    SignerAccount->>Account: execute(bytes32 mode, bytes executionData)
    Account->>Account: mode.isBatchedCall()
    opt If !mode.isBatchedCall()
        Account-->>SignerAccount: revert UnsupportedExecutionMode()
    end
    
    Account->>Account: abi.decode(executionData) to Call[]
    Account->>Account: Create BatchedCall with calls and mode.revertOnFailure()
    Account->>Account: execute(batchedCall)
    Account->>Account: Check if sender keyHash is owner or admin
    Account->>Account: _processBatch(batchedCall, keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _process(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: beforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: afterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.revertOnFailure
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
    participant Account as Calibur
    participant Hook
    participant Target
    
    Signer->>Signer: Create UserOperation with (keyHash, signature, hookData)
    Signer->>Signer: Sign userOpHash
    Signer->>Bundler: Submit UserOperation
    
    Bundler->>+EntryPoint: handleOps([userOp], beneficiary)
    EntryPoint->>+Account: validateUserOp(userOp, userOpHash, missingAccountFunds)
    
    Account->>Account: _payEntryPoint(missingAccountFunds)
    Account->>Account: Decode signature to (keyHash, signature, hookData)
    Account->>Account: getKey(keyHash)
    Account->>Account: key.verify(userOpHash, signature)
    Account->>Account: getKeySettings(keyHash)
    
    opt If hook has AFTER_VALIDATE_USER_OP permission
        Account->>Hook: afterValidateUserOp(keyHash, userOp, userOpHash, hookData)
    end
    
    Account->>Account: Return validationData with expiry and isValid
    Account-->>-EntryPoint: validationData
    
    EntryPoint->>+Account: executeUserOp(userOp, userOpHash)
    Account->>Account: Decode signature to extract keyHash
    Account->>Account: Decode callData to BatchedCall
    Account->>Account: _processBatch(batchedCall, keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _process(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: beforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: afterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.revertOnFailure
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
    participant Account as Calibur
    participant Hook
    
    VerifyingContract->>+Account: isValidSignature(bytes32 digest, bytes wrappedSignature)
    
    alt ERC7739 Sentinel Check
        Account->>Account: Check if wrappedSignature length is 0 and digest matches sentinel
        Account-->>VerifyingContract: Return 0x77390001
    end
    
    Account->>Account: Decode wrappedSignature to (keyHash, signature, hookData)
    Account->>Account: getKey(keyHash)
    
    alt Caller is safe listed
        Account->>Account: key.verify(digest, signature)
    else Caller is address(0) (offchain call)
        Account->>Account: _isValidNestedPersonalSig(key, digest, domainSeparator(), signature)
    else Standard ERC7739 verification
        Account->>Account: _isValidTypedDataSig(key, digest, domainBytes(), signature)
    end
    
    opt If !isValid
        Account-->>VerifyingContract: Return _1271_INVALID_VALUE
    end
    
    Account->>Account: getKeySettings(keyHash)
    Account->>Account: _checkExpiry(settings)
    
    opt If hook has AFTER_IS_VALID_SIGNATURE permission
        Account->>Hook: afterIsValidSignature(keyHash, digest, hookData)
    end
    
    Account-->>-VerifyingContract: Return _1271_MAGIC_VALUE
```

### ERC7914 Native ETH Approval Flow

```mermaid
sequenceDiagram
    participant Caller
    participant Account as Calibur
    participant Spender
    
    Caller->>+Account: approveNative(spender, amount)
    Account->>Account: Check onlyThis modifier
    Account->>Account: allowance[spender] = amount
    Account->>Account: Emit ApproveNative event
    Account-->>-Caller: Return true

    alt Approve Transient
        Caller->>+Account: approveNativeTransient(spender, amount)
        Account->>Account: Check onlyThis modifier
        Account->>Account: TransientAllowance.set(spender, amount) 
        Account->>Account: Emit ApproveNativeTransient event
        Account-->>-Caller: Return true
    end
    
    Spender->>+Account: transferFromNative(account, recipient, amount)
    Account->>Account: Check caller allowance
    Account->>Account: Update allowance if not max
    Account->>+recipient: Transfer ETH value
    recipient-->>-Account: Success
    Account->>Account: Emit TransferFromNative event
    Account-->>-Spender: Return true
    
    alt Transient Transfer
        Spender->>+Account: transferFromNativeTransient(account, recipient, amount)
        Account->>Account: Check caller transient allowance
        Account->>Account: Update transient allowance if not max
        Account->>+recipient: Transfer ETH value
        recipient-->>-Account: Success
        Account->>Account: Emit TransferFromNativeTransient event
        Account-->>-Spender: Return true
    end
```
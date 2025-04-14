#!/usr/bin/env node
import {
    privateKeyToAccount,
    type PrivateKeyAccount,
  
  } from 'viem/accounts'
  import {
    createWalletClient,
    http,
    type WalletClient,
    type Address,
    toHex,
    pad,
    hashTypedData as hashTypedDataV4,
    hashDomain,
    getTypesForEIP712Domain,
    hashStruct
  } from 'viem'
  
import { DOMAIN_NAME as VERIFIER_DOMAIN_NAME, DOMAIN_VERSION as VERIFIER_DOMAIN_VERSION, InputData} from './utils/constants';
import { hashTypedData as wrappedHashTypedData } from 'viem/experimental/erc7739'
import { erc7739Actions } from 'viem/experimental'

// Read command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("Usage: sign-wrapped-typed-data <privateKey> <verifyingContract>");
  process.exit(1);
}

// Define the struct types
const PermitSingleTypes = {
    PermitSingle: [
      { name: 'details', type: 'PermitDetails' },
      { name: 'spender', type: 'address' },
      { name: 'sigDeadline', type: 'uint256' }
    ],
    PermitDetails: [
      { name: 'token', type: 'address' },
      { name: 'amount', type: 'uint160' },
      { name: 'expiration', type: 'uint48' },
      { name: 'nonce', type: 'uint48' }
    ]
  } as const;
  
type PermitSingle = {
    details: PermitDetails;
    spender: Address;
    sigDeadline: bigint;
}

type PermitDetails = {
    token: Address;
    amount: bigint;
    expiration: number;
    nonce: number;
}

interface SignWrappedTypedDataInputData extends InputData {
    appDomainName: string;
    appDomainVersion: string;
    appVerifyingContract: Address;
    contents: PermitSingle;
}

// Parse the JSON input
const jsonInput = JSON.parse(args[0]) as SignWrappedTypedDataInputData;
const { privateKey, verifyingContract, appDomainName, appDomainVersion, appVerifyingContract, contents } = jsonInput;

const account = privateKeyToAccount(pad(toHex(BigInt(privateKey))));
 
const walletClient = createWalletClient({
    account,
    transport: http('http://127.0.0.1:8545') // Use Anvil's default URL for local development
}).extend(erc7739Actions()) 

async function signWrappedTypedData(): Promise<void> {
    try {
        const appDomain = {
            name: appDomainName,
            version: appDomainVersion,
            verifyingContract: appVerifyingContract,
            chainId: 31337, // Default Anvil chain ID
            // salt: '0x0000000000000000000000000000000000000000000000000000000000000000' as `0x${string}`,
        }
        const verifierDomain = {
            name: VERIFIER_DOMAIN_NAME,
            version: VERIFIER_DOMAIN_VERSION,
            verifyingContract: verifyingContract,
            chainId: 31337, // Default Anvil chain ID
            salt: '0x0000000000000000000000000000000000000000000000000000000000000000' as `0x${string}`,
        }

        const wrappedSignature = await walletClient.signTypedData({
            account,
            domain: appDomain,
            types: PermitSingleTypes,
            primaryType: 'PermitSingle',
            message: contents,
            verifierDomain: verifierDomain,
        })  

        // signature is first 65 bytes of wrappedSignature + 0x
        const signatureLength = 130 // 65 * 2
        const start = 2; // skip the first 0x
        const signature = '0x' + wrappedSignature.slice(start, start + signatureLength);
    
        // Return the signature
        process.stdout.write(signature);
        process.exit(0);
    } catch (error) {
        console.error('Error signing wrapped typed data:', error);
        process.exit(1);
    }
}

signWrappedTypedData().catch(console.error); 

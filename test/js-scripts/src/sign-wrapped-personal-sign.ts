#!/usr/bin/env node
import {
    privateKeyToAccount,  
  } from 'viem/accounts'
  import {
    createWalletClient,
    http,
    type Address,
    toHex,
    pad,
    createPublicClient,
    verifyMessage,
  } from 'viem'
  
import { DOMAIN_NAME as VERIFIER_DOMAIN_NAME, DOMAIN_VERSION as VERIFIER_DOMAIN_VERSION, InputData} from './utils/constants';
import { erc7739Actions } from 'viem/experimental'
import { hashMessage } from 'viem/experimental/erc7739';

// Read command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("Usage: sign-wrapped-personal-sign <privateKey> <verifyingContract> <message>");
  process.exit(1);
}

interface WrappedPersonalSignInputData extends InputData {
    message: string;
}

// Parse the JSON input
const jsonInput = JSON.parse(args[0]) as WrappedPersonalSignInputData;
const { privateKey, verifyingContract, message } = jsonInput;

const account = privateKeyToAccount(pad(toHex(BigInt(privateKey))));

const publicClient = createPublicClient({
    transport: http('http://127.0.0.1:8545') // Use Anvil's default URL for local development
})
 
const walletClient = createWalletClient({
    account,
    transport: http('http://127.0.0.1:8545') // Use Anvil's default URL for local development
}).extend(erc7739Actions()) 

async function signWrappedPersonalSign(): Promise<void> {
    try {
        const verifierDomain = {
            name: VERIFIER_DOMAIN_NAME,
            version: VERIFIER_DOMAIN_VERSION,
            verifyingContract: verifyingContract,
            chainId: 31337, // Default Anvil chain ID
            // Salt is omitted from personal_sign
        }

        // For some reason this is not working 
        const signature = await walletClient.signMessage({
            account,
            message: message,
            verifierDomain: verifierDomain,
        })
        // Return the signature
        process.stdout.write(signature);
        process.exit(0);
    } catch (error) {
        console.error('Error signing wrapped typed data:', error);
        process.exit(1);
    }
}

signWrappedPersonalSign().catch(console.error); 

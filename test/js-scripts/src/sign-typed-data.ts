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
} from 'viem'

import { DOMAIN_NAME, DOMAIN_VERSION, types, Call} from './utils/constants';


interface InputData {
  privateKey: string;
  verifyingContract: Address;
  calls: Call[];
  nonce: number;
}

// Read command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log("Usage: sign-typed-data <privateKey> <verifyingContract> <calls>");
  process.exit(1);
}

// Parse the JSON input
const jsonInput = JSON.parse(args[0]) as InputData;
const { privateKey, verifyingContract, calls, nonce } = jsonInput;

const account = privateKeyToAccount(pad(toHex(BigInt(privateKey))));

// Define the domain type structure
const domain = {
  name: DOMAIN_NAME,
  version: DOMAIN_VERSION,
  chainId: 31337, // Default Anvil chain ID
  verifyingContract
} as const;



// Create a wallet client
const walletClient: WalletClient = createWalletClient({
  account,
  transport: http('http://127.0.0.1:8545') // Use Anvil's default URL for local development
});

async function signTypedData(): Promise<void> {
  try {
    const signature = await walletClient.signTypedData({
      account,
      domain,
      types,
      primaryType: 'Execute',
      message: {
        calls: calls,
        nonce: nonce,
      }
    });
    // Return the signature
    process.stdout.write(signature);
    process.exit(0);
  } catch (error) {
    console.error('Error signing typed data:', error);
    process.exit(1);
  }
}

signTypedData().catch(console.error); 
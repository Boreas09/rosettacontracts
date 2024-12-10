DENEME

# Rosetta Contracts

Rosetta Contracts is a smart contract library written in Cairo. It allows users to interact with Starknet with their Layer 1 signatures. This package has three subfolders: accounts, verifier, and Lens.

## Accounts

Starknet account abstraction smart contracts execute and validate transactions with Ethereum call data and signature. This account allows users to interact with Starknet with their Layer 1 accounts.

## Verifier

Utility smart contracts that format Ethereum call data according to ABI passed. It also validates Ethereum signature and call data formatting. Account contracts use this utility before executing the transactions.

## Lens

The Lens is a permissionless smart contract that registers and maps Ethereum addresses to the Starknet address equivalent and vice versa. Everyone can register any address to Lens. Only Account factory has a right to match any address with any address it passes. This ability is needed to match newly deployed account contracts with Layer 1 addresses.

Sepolia Deployment : 0x055f17a002c440e850c7005180ae803c7d2752f554add2ef7f3a740a24fadfa6 (Lens Dev)

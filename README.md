# 🛡️ Interoperable Vaccine Passport with Zero-Knowledge Proofs

Welcome to a privacy-first solution for verifying immunization status! This Web3 project builds an interoperable vaccine passport app on the Stacks blockchain using Clarity smart contracts. It allows users to prove their vaccination status for travel, events, or access without revealing sensitive personal details like identity, medical history, or exact vaccination dates—leveraging zero-knowledge proofs (ZKPs) for verification.

This addresses the real-world problem of balancing public health needs (e.g., preventing disease spread during pandemics) with individual privacy rights, enabling secure, cross-border interoperability while complying with data protection laws like GDPR.

## ✨ Features

🔒 Generate and store ZKP-based vaccination proofs on-chain  
✅ Verify immunization status without exposing personal data  
🌍 Interoperable across borders/institutions via standardized proofs  
📱 User-controlled wallet integration for proof management  
🚫 Revoke or update proofs securely (e.g., for boosters)  
🔄 Cross-chain compatibility hooks for future expansions  
📊 Audit trails for health authorities without compromising privacy  
🛡️ Fraud prevention through immutable blockchain records  

## 🛠 How It Works

The system uses 8 Clarity smart contracts to handle different aspects of the passport lifecycle, ensuring modularity, security, and scalability. Users interact via a dApp or mobile wallet. Vaccination data is never stored in plain text—instead, it's hashed and proven via ZKPs (using libraries like Circom for off-chain proof generation, verified on-chain).

**For Users (Patients)**  
- Receive a vaccination certificate from a trusted issuer (e.g., clinic).  
- Generate a ZKP off-chain proving key attributes (e.g., "fully vaccinated against COVID-19 as of 2023").  
- Call the `UserProofRegistry` contract to register the proof hash.  
- When verification is needed (e.g., at an airport), share a ZKP challenge-response via the `VerificationEngine` contract—provers reveal nothing beyond "valid/invalid."  

**For Issuers (Clinics/Health Authorities)**  
- Authenticate via the `IssuerRegistry` contract.  
- Issue encrypted certificates and sign ZKP setups using the `CertificateIssuer` contract.  
- Update or revoke via the `RevocationManager` for expired boosters.  

**For Verifiers (Airlines, Venues, Borders)**  
- Query the `VerificationEngine` with a user's proof ID and challenge.  
- Get instant on-chain confirmation without accessing raw data.  
- Use the `AuditLogger` for compliance reporting (aggregated, anonymized stats).  

Interoperability is achieved through standardized ZKP schemas (e.g., based on Verifiable Credentials), allowing proofs to be portable to other blockchains via bridges.

## 📜 Smart Contracts Overview

This project involves 8 Clarity smart contracts for a robust, decentralized architecture:

1. **UserProofRegistry.clar**: Handles user registration of ZKP hashes, linking to wallet addresses for ownership.  
2. **IssuerRegistry.clar**: Manages whitelisting and authentication of trusted issuers (e.g., hospitals).  
3. **CertificateIssuer.clar**: Issues signed vaccination certificates and initializes ZKP parameters.  
4. **VerificationEngine.clar**: Core contract for on-chain ZKP verification using proof challenges.  
5. **RevocationManager.clar**: Allows issuers to revoke proofs (e.g., for fraud) while maintaining user privacy.  
6. **UpdateHandler.clar**: Facilitates secure updates to proofs (e.g., adding booster shots) without re-revealing data.  
7. **AuditLogger.clar**: Logs anonymized verification events for regulatory audits.  
8. **InteropBridge.clar**: Provides hooks for cross-chain proof exports/imports (e.g., via SIP-010 tokens).  

Each contract is designed to be upgradable via STX governance, with read-only functions for queries and restricted writes for security.

## 🚀 Getting Started

- Install the Clarity CLI and Stacks wallet.  
- Deploy contracts to the Stacks testnet.  
- Integrate with a frontend dApp (e.g., using React and Hiro Wallet).  
- For ZKPs: Generate proofs off-chain with tools like snarkjs, then verify on-chain.  

Protect your health data like never before—privacy preserved, access granted!
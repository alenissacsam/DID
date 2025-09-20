# DID Smart Contracts (Foundry)

A modular, production-grade suite of Solidity contracts for decentralized identity (DID) and verifiable credentials on Ethereum-compatible chains. The system focuses on privacy-preserving verification, organization-managed credentials, and robust governance via dispute resolution.

This repo uses Foundry for builds/tests and OpenZeppelin libraries for security and standards.

## ✨ Highlights
- Modular identity and verification managers (Aadhaar, Income, Face, Mobile, Offline)
- Organization-managed credentials: ERC721 certificates and ERC1155 recognitions
- Cross-chain privacy primitives: Global Credential Anchor and CrossChainManager
- Account abstraction support (ERC-4337) with gas sponsorship tooling
- Transparent audit trail across the system via VerificationLogger
- Dispute Resolution module (kept) — GovernanceManager and SystemToken removed

## Architecture Overview

Core building blocks:
- Core
  - `UserIdentityRegistry` — registration and verification state for users
  - `VerificationLogger` — event log hub for auditability
  - `ContractRegistry` — registry of deployed contract addresses and metadata
- Verification
  - `AadhaarVerificationManager`, `IncomeVerificationManager`, `FaceVerificationManager`, `OfflineVerificationManager`, `MobileVerificationInterface`
- Organizations
  - `CertificateManager` (ERC721) — issue/ revoke certificates
  - `RecognitionManager` (ERC1155) — badges/recognitions
  - `OrganizationRegistryProxy` + `OrganizationLogic` + `OrganizationView`
- Privacy & Cross-Chain
  - `GlobalCredentialAnchor` — anchor/merkle roots for credentials
  - `CrossChainManager` — cross-chain sync/control utilities
  - `PrivacyManager` — privacy controls and access policy helpers
- Advanced Features
  - `AlchemyGasManager` — gas sponsorship via third-party paymasters
  - `EduCertEntryPoint`, `EduCertModularAccount`, `EduCertAccountFactory` — ERC-4337 account abstraction components
  - `MigrationManager`, `TrustScore`, `PaymasterManager` (updated to not require SystemToken)
- Governance
  - `DisputeResolution` — dispute lifecycle, arbitration, and execution
  - Removed: `GovernanceManager` and `SystemToken` (and `ISystemToken` interface)

Interfaces live under `src/interfaces/` and are imported per-contract (we replaced the monolithic `SharedInterfaces.sol`). Key interfaces: `IVerificationLogger`, `ITrustScore`, `IUserIdentityRegistry`, `IGuardianManager`, `IEntryPoint`, etc.

## Recent Changes
- Fully decoupled interfaces (removed `SharedInterfaces.sol`) and added specific interface files
- Removed economic tokenization: deleted `SystemToken.sol` and `ISystemToken.sol`
- Removed governance coordinator: deleted `GovernanceManager.sol`
- Updated `DisputeResolution.sol` to work without a token bond; the module is preserved
- Updated `PaymasterManager.sol` to remove token dependency and related purchase flow

## Getting Started

Prerequisites:
- Foundry toolchain (forge, cast, anvil)
- Node.js (optional, for scripts or tooling)

Setup:
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install deps (submodules/libs are already vendored)
forge install

# Build
forge build

# Run tests
forge test
```

## Configuration
- `foundry.toml` — compiler, optimizer, remappings
- `remappings.txt` are inherited from vendored libs when needed

Environment variables (optional):
- None strictly required for build/test. Integration/interaction scripts may expect RPC URLs and private keys via standard Foundry envs:
  - `RPC_URL`, `ETHERSCAN_API_KEY`, `PRIVATE_KEY`, etc.

## Deployment
This repo includes deployment and interaction artifacts in `broadcast/`. Example deployment scripts live under `script/` (for your app-specific flows) and `lib/foundry-devops/script/` for generic helpers.

Typical flow:
```bash
# Dry-run on Anvil fork
forge script script/DeployEduCertSystem.s.sol --fork-url $RPC_URL -vvvv

# Broadcast to a network
forge script script/DeployEduCertSystem.s.sol --rpc-url $RPC_URL --broadcast --verify -vvvv
```

Artifacts for prior runs are stored under `broadcast/*` by chain ID. Update script addresses and parameters as needed.

## Modules and Contracts
- Identity & Trust
  - `UserIdentityRegistry` — user registration, verification status
  - `TrustScore` — dynamic trust scoring and checks
- Verification Managers
  - `AadhaarVerificationManager` — Aadhaar-linked flows
  - `IncomeVerificationManager` — income proofs
  - `FaceVerificationManager` — biometric checks
  - `OfflineVerificationManager` — off-chain signed attestations (EIP-712)
  - `MobileVerificationInterface` — mobile number verification helpers
- Organizations
  - `CertificateManager` — ERC721 credentials
  - `RecognitionManager` — ERC1155 recognitions/badges
  - `OrganizationRegistryProxy` + `OrganizationLogic` + `OrganizationView`
- Privacy & Cross Chain
  - `GlobalCredentialAnchor`, `CrossChainManager`, `PrivacyManager`
- Account Abstraction + Gas
  - `EduCertEntryPoint`, `EduCertModularAccount`, `EduCertAccountFactory`
  - `AlchemyGasManager`, `PaymasterManager`
- Governance
  - `DisputeResolution` (tokenless bond post-change)

## Testing
```bash
forge test -vvv
```
Add unit tests under `test/` following Foundry conventions. Use `forge-std` utilities for assertions, cheats, and fuzzing.

## Security Notes
- Uses OpenZeppelin access control and standards
- Reentrancy protections where applicable
- Logs key security-affecting actions via `VerificationLogger`
- Review warnings produced by `forge build` and consider tightening rules over time

## FAQs
- Q: Why remove SystemToken?
  - A: Simplifies the protocol by dropping the native token dependency; reduces coupling and economic complexity.
- Q: Is governance gone?
  - A: The GovernanceManager was removed. DisputeResolution remains for adjudication and execution paths.
- Q: Can I plug in another token later?
  - A: Yes. You can reintroduce a bond mechanism by adding a generic ERC20 interface and checks in DisputeResolution if needed.

## Repository Guide
- `DEPLOYMENT_GUIDE.md` — step-by-step deployment
- `FINAL_REVIEW_SUMMARY.md` — high-level audit/review notes
- `SECURITY_FIXES_SUMMARY.md` — security-focused changes
- `JSONs/` — minified ABIs for integration
- `broadcast/` — deployment logs and artifacts

---
Maintained with Foundry. Contributions welcome.

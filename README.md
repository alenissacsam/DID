# DID Smart Contracts (Foundry)

A modular, production-grade suite of Solidity contracts for decentralized identity (DID) and verifiable credentials on Ethereum-compatible chains. The system focuses on privacy-preserving verification, organization-managed credentials, and robust governance via dispute resolution.

This repo uses Foundry for builds/tests and OpenZeppelin libraries for security and standards.

## ✨ Highlights
- Modular identity and verification managers (Aadhaar, Income, Face, Mobile, Offline)
- Organization-issued ERC721 certificates (badges/recognitions system removed to streamline scope)
- Cross-chain privacy primitives: Global Credential Anchor and CrossChainManager
- Account abstraction (ERC-4337) modular smart account with pluggable modules (session keys, subscriptions)
- Transparent audit trail via `VerificationLogger` + standardized events & custom errors
- Dispute Resolution module retained (tokenless) — GovernanceManager & SystemToken removed

## Architecture Overview

Core building blocks:
- Core
  - `UserIdentityRegistry` — registration and verification state for users
  - `VerificationLogger` — event log hub for auditability
  - `ContractRegistry` — registry of deployed contract addresses and metadata
- Verification
  - `AadhaarVerificationManager`, `IncomeVerificationManager`, `FaceVerificationManager`, `OfflineVerificationManager`, `MobileVerificationInterface`
- Organizations
  - `CertificateManager` (ERC721) — issue / revoke certificates (configurable trust score rewards)
  - `OrganizationRegistryProxy` + `OrganizationLogic` + `OrganizationView`
- Privacy & Cross-Chain
  - `GlobalCredentialAnchor` — anchor/merkle roots for credentials
  - `CrossChainManager` — cross-chain sync/control utilities
  - `PrivacyManager` — privacy controls and access policy helpers
- Advanced Features
  - `AlchemyGasManager` — gas sponsorship via third-party paymasters
  - `IdentityEntryPoint`, `IdentityModularAccount`, `IdentityAccountFactory` — ERC-4337 account abstraction components
  - `MigrationManager`, `TrustScore`, `PaymasterManager` (updated to not require SystemToken)
  - Modular Account Modules (new): `SessionKeyModule`, `SubscriptionModule` (see "Modular Account Architecture" below)
- Governance
  - `DisputeResolution` — dispute lifecycle, arbitration, and execution
  - Removed: `GovernanceManager` and `SystemToken` (and `ISystemToken` interface)

Interfaces live under `src/interfaces/` and are imported per-contract (we replaced the monolithic `SharedInterfaces.sol`). Key interfaces: `IVerificationLogger`, `ITrustScore`, `IUserIdentityRegistry`, `IGuardianManager`, `IEntryPoint`, etc.

## Recent Changes
Refactor wave (September 2025):
- Session Key overhaul: external EOA signer required, bytes4 selector allowlist (removed string list + gasLimit field), domain overwrite logic, custom errors.
- Subscription module enhanced: failure no longer reverts (returns bool), grace period + overdue tracking, auto-cancel after grace, events `SubscriptionPaymentFailed`, `SubscriptionOverdue`, `SubscriptionCanceled`.
- Account locking: `lockAccount` / `unlockAccount` gates module creation & execution; emits `AccountLocked` / `AccountUnlocked`.
- Recognition / badge system removed (`RecognitionManager` deleted) to reduce surface area.
- Certificate rewards configurable: `issueReward` / `revokePenalty` with governance setter + event.
- Custom errors adopted across new & refactored contracts for gas savings and clearer failure reasons.
- Documentation & README updated to reflect modular architecture changes.
- Cleaned deployment & interaction scripts to remove recognition references.
Earlier structural changes:
- Fully decoupled interfaces (removed `SharedInterfaces.sol`).
- Removed economic tokenization (deleted `SystemToken.sol`, `ISystemToken.sol`).
- Removed `GovernanceManager`; dispute resolution retained and tokenless.
- Updated `PaymasterManager.sol` to remove token dependency.

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
# Dry-run on Anvil
forge script script/deploy/DeployAll.s.sol:DeployAll --rpc-url $RPC_URL -vvvv

# Broadcast to a network (set PRIVATE_KEY)
forge script script/deploy/DeployAll.s.sol:DeployAll --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
```

Artifacts for prior runs are stored under `broadcast/*` by chain ID. Update script addresses and parameters as needed.

## Scripts

The `script/` folder is organized by purpose:

- `script/deploy/`
  - `DeployAll.s.sol` — Deploys VerificationLogger, TrustScore, and UserIdentityRegistry.
- `script/zk/`
  - `DeployAndWireZK.s.sol` — Deploy ZKProofManager and register proof verifiers; can also anchor a Merkle root.
  - `DeployZK.s.sol` — Register existing verifiers to an existing ZKProofManager.
- `script/roles/`
  - `BootstrapRoles.s.sol` — Grants SCORE_MANAGER_ROLE on TrustScore to the registry.
  - `GrantLoggerRole.s.sol` — Grants LOGGER_ROLE on VerificationLogger to a target (e.g., TrustScore or Registry).
- `script/identity/`
  - `RegisterIdentity.s.sol` — Registers a user identity with a commitment.
  - `SetIdentityMetadata.s.sol` — Sets the identity metadata URI for a user.
- `script/examples/`
  - `Interactions.s.sol` — Placeholder for ad-hoc demos and testing.

Usage examples (env: RPC_URL, PRIVATE_KEY):

- Deploy core:
  - forge script script/deploy/DeployAll.s.sol:DeployAll --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
- ZK: deploy and wire (requires AGE_VERIFIER_ADDR, ATTR_VERIFIER_ADDR, INCOME_VERIFIER_ADDR, AGE_MAX_VERIFIER_ADDR):
  - forge script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
- ZK: wire existing manager (requires ZKPM_ADDRESS, AGE_GTE_VERIFIER, AGE_LTE_VERIFIER, ATTR_EQ_VERIFIER, INCOME_GTE_VERIFIER):
  - forge script script/zk/DeployZK.s.sol:DeployZK --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
- Roles:
  - SCORE_MANAGER_ROLE to Registry: forge script script/roles/BootstrapRoles.s.sol:BootstrapRoles --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
  - LOGGER_ROLE to TrustScore or Registry: forge script script/roles/GrantLoggerRole.s.sol:GrantLoggerRole --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
- Identity:
  - Register: forge script script/identity/RegisterIdentity.s.sol:RegisterIdentity --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
  - Set metadata: forge script script/identity/SetIdentityMetadata.s.sol:SetIdentityMetadata --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv

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
  - `CertificateManager` — ERC721 credentials (configurable trust score deltas)
  - `OrganizationRegistryProxy` + `OrganizationLogic` + `OrganizationView`
- Privacy & Cross Chain
  - `GlobalCredentialAnchor`, `CrossChainManager`, `PrivacyManager`
  - `ZKProofManager` — manage Groth16 proof types and anchored Merkle roots
- Account Abstraction + Gas
  - `IdentityEntryPoint`, `IdentityModularAccount`, `IdentityAccountFactory`
  - `AlchemyGasManager`, `PaymasterManager`
  - Modules: `SessionKeyModule` (external signer, selector allowlist, daily value limits), `SubscriptionModule` (recurring payments w/ grace + auto-cancel) — extensible registry
- Governance
  - `DisputeResolution` (tokenless bond post-change)

## Testing
```bash
forge test -vvv
```
Add unit tests under `test/` following Foundry conventions. Use `forge-std` utilities for assertions, cheats, and fuzzing.

### Modular Account Tests
Representative tests:
- `SessionKeyModule.t.sol` — creation + selector-scoped call path
- `SubscriptionModule.t.sol` — success path, failure -> grace, grace -> auto-cancel, recovery after failure
- `IdentityModularAccountLock.t.sol` — lock/unlock gating
- `CertificateManagerConfig.t.sol` — configurable reward & penalty paths

### Subscription Failure Semantics
`executePayment(id)` returns `true` on success, `false` on payment failure OR auto-cancel (after grace expiry). It never reverts for ordinary payment failures so state (grace window, failedAttempts) persists. Only validation errors (non-existent / inactive / not due) revert via custom errors.

### Error Strategy & Events
- Custom errors: e.g., `ErrorAccountLocked`, `ErrorNotDue(nextPayment, nowTs)`, `ErrorSubInactive` reduce gas vs revert strings.
- Event taxonomy: account (`AccountLocked/Unlocked`), session keys (`SessionKeyReplaced`, etc.), subscriptions (`SubscriptionCreated`, `SubscriptionPaymentFailed`, `SubscriptionOverdue`, `SubscriptionCanceled`, `SubscriptionPayment`).

### Account Locking
When locked, actions that create or execute module operations revert. Unlock restores normal behavior; read paths unaffected.

End-to-end and fuzz suites remain unchanged and ensure no regression after modularization.

### Quick Summary of Current Coverage
- Core identity + verification managers: unit + fuzz
- Modular account: basic positive paths; planned enhancements include signature realism for session keys and multi-cycle subscription simulations.

For deep design notes see `docs/modular_account_architecture.md`.

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

## Zero-Knowledge (ZK) Addendum
End-to-end ZK pipeline and contracts are included:
- Circuits: `tools/zk-circuits/circuits/*`
- Automation: `tools/zk-circuits/Makefile` (powers of tau, compile, verifiers, proofs)
- Verifiers: generated under `tools/zk-circuits/build/*.sol`
- Proof Manager: `src/verification/ZKProofManager.sol`

Quick start:
```bash
cd tools/zk-circuits
make all          # ptau + compile all + generate verifiers

# Deploy verifiers (each contains Groth16Verifier)
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY tools/zk-circuits/build/AgeVerifier.sol:Groth16Verifier
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY tools/zk-circuits/build/AgeMaxVerifier.sol:Groth16Verifier
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY tools/zk-circuits/build/AttrVerifier.sol:Groth16Verifier
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY tools/zk-circuits/build/IncomeVerifier.sol:Groth16Verifier

# Deploy ZKProofManager and register verifiers
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/verification/ZKProofManager.sol:ZKProofManager
export ZKPM_ADDRESS=0x...
export AGE_GTE_VERIFIER=0x...
export AGE_LTE_VERIFIER=0x...
export ATTR_EQ_VERIFIER=0x...
export INCOME_GTE_VERIFIER=0x...
forge script script/deployZK.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
```

For how to generate inputs from encrypted identity bundles and produce proofs, see `docs/identity_storage_and_zk_pipeline.md`.

Super-detailed wiring and pipeline: `docs/zk_end_to_end_wiring.md`.

Frontend integration (viem/ethers + AA bundler/paymaster): `docs/frontend_integration_guide.md`.

Modular smart account design: `docs/modular_account_architecture.md`.

---
Maintained with Foundry. Contributions welcome.

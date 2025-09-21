# ZK Circuits for Identity Attributes

This folder contains Circom circuits to prove facts about private identity attributes committed with Poseidon inside a Merkle tree.

What’s included:
- age_check.circom — prove age >= threshold (or <=)
- attr_equals.circom — prove attribute equals a value (e.g., name, DOB, Aadhaar last-4)
- income_check.circom — prove income >= threshold
 - age_max_check.circom — prove age <= threshold

Inputs model:
- Private inputs:
  - valueField: field-encoded attribute value (we pack ASCII to a field)
  - salt: random field element used in the leaf
  - pathElements[], pathIndices[]: Merkle path to the committed leaf
- Public inputs:
  - root: Merkle root (Poseidon-based) anchored on-chain
  - policy parameter (e.g., minAge)

All circuits compute leaf = Poseidon(valueField, salt) and verify Merkle inclusion to the given root, then enforce the policy.

See the helper script in tools/identity-pipeline/src/run.js for how we pack ASCII values to a field and compute Poseidon leaves.

## How to compile (example)

You need circom and snarkjs installed. Suggested Merkle depth: 20 or 32.

Example (age >=):
- circom circuits/age_check.circom --r1cs --wasm --sym -o build
- snarkjs groth16 setup build/age_check.r1cs pot16_final.ptau age_check_0000.zkey
- snarkjs zkey contribute age_check_0000.zkey age_check_final.zkey

Inputs shape (age_check):
- Private: valueField, salt, pathElements[depth], pathIndices[depth]
- Public: root, minAge, nowYear

Packing values:
- Strings (name, DOB) are packed as ASCII bytes to a single field element.
- Integers (birthYear, income) are directly set as field numbers.

Ensure the Merkle root matches what’s anchored on-chain.

## Deploying verifiers
snarkjs emits a contract named `Groth16Verifier` in each generated Solidity file. Do NOT copy multiple of these into `src` at the same time, or you'll get duplicate contract names.

Recommended deployment from the generated files:

```bash
# After `make verifiers`
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
  tools/zk-circuits/build/AgeVerifier.sol:Groth16Verifier

forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
  tools/zk-circuits/build/AgeMaxVerifier.sol:Groth16Verifier

forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
  tools/zk-circuits/build/AttrVerifier.sol:Groth16Verifier

forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
  tools/zk-circuits/build/IncomeVerifier.sol:Groth16Verifier
```

Then register the deployed addresses in `ZKProofManager` using `script/deployZK.s.sol` with env vars:

```bash
export ZKPM_ADDRESS=0x...    # deployed ZKProofManager
export AGE_GTE_VERIFIER=0x...
export AGE_LTE_VERIFIER=0x...
export ATTR_EQ_VERIFIER=0x...
export INCOME_GTE_VERIFIER=0x...

forge script script/deployZK.s.sol \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
```

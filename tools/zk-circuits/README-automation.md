# Circuit Compilation and Verification Automation

This Makefile provides complete automation for compiling Circom circuits, running powers of tau ceremonies, and generating Solidity verifiers.

## Prerequisites
- circom installed (`npm install -g circom@latest`)
- snarkjs installed (`npm install -g snarkjs@latest`)
- Node.js and npm for the helper scripts

## Usage

### Compile all circuits and generate verifiers
```bash
make all
```

### Individual circuit compilation
```bash
make age-gte      # Age >= threshold
make age-lte      # Age <= threshold  
make attr-equals  # Attribute equals
make income-gte   # Income >= threshold
```

### Generate input files from encrypted bundle
```bash
make inputs       # Decrypt bundle and generate all input files
```

### Generate proofs for all circuits
```bash
make proofs       # Generate proofs using the input files
```

### Clean build artifacts
```bash
make clean
```

## Directory Structure After Build
```
tools/zk-circuits/
├── build/
│   ├── age_check.r1cs
│   ├── age_check_js/
│   ├── AgeVerifier.sol
│   ├── age_check_final.zkey
│   └── ... (other circuits)
├── ptau/
│   └── pot16_final.ptau
└── proofs/
    ├── age_gte_proof.json
    ├── age_gte_public.json
    └── ... (other proofs)
```

## Integration with Contracts
The generated `*Verifier.sol` files can be deployed and their addresses used with `ZKProofManager.sol`.
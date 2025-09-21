# Circuit compilation and proof generation automation
SHELL := /bin/bash
.PHONY: all clean setup ptau age-gte age-lte attr-equals income-gte inputs proofs verifiers

# Directories
BUILD_DIR := build
PTAU_DIR := ptau
PROOF_DIR := proofs
CIRCUITS_DIR := circuits
PIPELINE_DIR := ../identity-pipeline

# Tools (override with environment if needed)
CIRCOM ?= circom
SNARKJS ?= npx snarkjs
INCLUDE_DIR ?= node_modules/circomlib/circuits

# Files
PTAU_FILE := $(PTAU_DIR)/pot16_final.ptau
CIRCUITS := age_check age_max_check attr_equals income_check
VERIFIERS := AgeVerifier AgeMaxVerifier AttrVerifier IncomeVerifier

# Default target
all: setup ptau $(CIRCUITS) verifiers

# Setup directories
setup:
	@mkdir -p $(BUILD_DIR) $(PTAU_DIR) $(PROOF_DIR)

# Powers of tau ceremony (run once)
ptau: $(PTAU_FILE)

$(PTAU_FILE): | setup
	@echo "🔧 Running powers of tau ceremony..."
	$(SNARKJS) powersoftau new bn128 16 $(PTAU_DIR)/pot16_0000.ptau -v
	$(SNARKJS) powersoftau contribute $(PTAU_DIR)/pot16_0000.ptau $(PTAU_DIR)/pot16_0001.ptau --name="First contribution" -v -e="random entropy"
	$(SNARKJS) powersoftau beacon $(PTAU_DIR)/pot16_0001.ptau $(PTAU_DIR)/pot16_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
	$(SNARKJS) powersoftau prepare phase2 $(PTAU_DIR)/pot16_beacon.ptau $(PTAU_FILE) -v
	@echo "✅ Powers of tau ceremony completed"

# Individual circuit compilation
age_check: $(BUILD_DIR)/age_check_final.zkey
age_max_check: $(BUILD_DIR)/age_max_check_final.zkey
attr_equals: $(BUILD_DIR)/attr_equals_final.zkey
income_check: $(BUILD_DIR)/income_check_final.zkey

# Generic circuit compilation rule
$(BUILD_DIR)/%_final.zkey: $(CIRCUITS_DIR)/%.circom $(PTAU_FILE) | setup
	@echo "🔧 Compiling circuit: $*"
	$(CIRCOM) -l $(INCLUDE_DIR) $(CIRCUITS_DIR)/$*.circom --r1cs --wasm --sym -o $(BUILD_DIR) --O1
	$(SNARKJS) groth16 setup $(BUILD_DIR)/$*.r1cs $(PTAU_FILE) $(BUILD_DIR)/$*_0000.zkey
	$(SNARKJS) zkey contribute $(BUILD_DIR)/$*_0000.zkey $(BUILD_DIR)/$*_final.zkey --name="First contribution" -v -e="random entropy"
	$(SNARKJS) zkey export verificationkey $(BUILD_DIR)/$*_final.zkey $(BUILD_DIR)/$*_verification_key.json
	@echo "✅ Circuit $* compiled successfully"

# Generate Solidity verifiers
verifiers: $(BUILD_DIR)/AgeVerifier.sol $(BUILD_DIR)/AgeMaxVerifier.sol $(BUILD_DIR)/AttrVerifier.sol $(BUILD_DIR)/IncomeVerifier.sol

$(BUILD_DIR)/AgeVerifier.sol: $(BUILD_DIR)/age_check_final.zkey
	$(SNARKJS) zkey export solidityverifier $(BUILD_DIR)/age_check_final.zkey $(BUILD_DIR)/AgeVerifier.sol
	@echo "✅ AgeVerifier.sol generated"

$(BUILD_DIR)/AgeMaxVerifier.sol: $(BUILD_DIR)/age_max_check_final.zkey
	$(SNARKJS) zkey export solidityverifier $(BUILD_DIR)/age_max_check_final.zkey $(BUILD_DIR)/AgeMaxVerifier.sol
	@echo "✅ AgeMaxVerifier.sol generated"

$(BUILD_DIR)/AttrVerifier.sol: $(BUILD_DIR)/attr_equals_final.zkey
	$(SNARKJS) zkey export solidityverifier $(BUILD_DIR)/attr_equals_final.zkey $(BUILD_DIR)/AttrVerifier.sol
	@echo "✅ AttrVerifier.sol generated"

$(BUILD_DIR)/IncomeVerifier.sol: $(BUILD_DIR)/income_check_final.zkey
	$(SNARKJS) zkey export solidityverifier $(BUILD_DIR)/income_check_final.zkey $(BUILD_DIR)/IncomeVerifier.sol
	@echo "✅ IncomeVerifier.sol generated"

# Convenience targets
age-gte: age_check
age-lte: age_max_check
attr-equals: attr_equals
income-gte: income_check

# Generate input files from encrypted bundle
inputs:
	@echo "🔧 Decrypting bundle and generating input files..."
	cd $(PIPELINE_DIR) && node src/decrypt.js
	cd $(PIPELINE_DIR) && node src/generate-inputs.js
	@echo "✅ Input files generated in $(PIPELINE_DIR)/.out/"

# Generate proofs using input files
proofs: $(PROOF_DIR)/age_gte_proof.json $(PROOF_DIR)/age_lte_proof.json $(PROOF_DIR)/attr_name_proof.json $(PROOF_DIR)/attr_dob_proof.json $(PROOF_DIR)/income_gte_proof.json

$(PROOF_DIR)/age_gte_proof.json: $(BUILD_DIR)/age_check_final.zkey | inputs
	@echo "🔧 Generating age >= proof..."
	$(SNARKJS) wtns calculate $(BUILD_DIR)/age_check_js/age_check.wasm $(PIPELINE_DIR)/.out/input.age_gte.json $(BUILD_DIR)/age_check_js/witness.wtns
	$(SNARKJS) groth16 prove $(BUILD_DIR)/age_check_final.zkey $(BUILD_DIR)/age_check_js/witness.wtns $(PROOF_DIR)/age_gte_proof.json $(PROOF_DIR)/age_gte_public.json
	@echo "✅ Age >= proof generated"

$(PROOF_DIR)/age_lte_proof.json: $(BUILD_DIR)/age_max_check_final.zkey | inputs
	@echo "🔧 Generating age <= proof..."
	$(SNARKJS) wtns calculate $(BUILD_DIR)/age_max_check_js/age_max_check.wasm $(PIPELINE_DIR)/.out/input.age_lte.json $(BUILD_DIR)/age_max_check_js/witness.wtns
	$(SNARKJS) groth16 prove $(BUILD_DIR)/age_max_check_final.zkey $(BUILD_DIR)/age_max_check_js/witness.wtns $(PROOF_DIR)/age_lte_proof.json $(PROOF_DIR)/age_lte_public.json
	@echo "✅ Age <= proof generated"

$(PROOF_DIR)/attr_name_proof.json: $(BUILD_DIR)/attr_equals_final.zkey | inputs
	@echo "🔧 Generating name equals proof..."
	$(SNARKJS) wtns calculate $(BUILD_DIR)/attr_equals_js/attr_equals.wasm $(PIPELINE_DIR)/.out/input.attr_name_equals.json $(BUILD_DIR)/attr_equals_js/witness.wtns
	$(SNARKJS) groth16 prove $(BUILD_DIR)/attr_equals_final.zkey $(BUILD_DIR)/attr_equals_js/witness.wtns $(PROOF_DIR)/attr_name_proof.json $(PROOF_DIR)/attr_name_public.json
	@echo "✅ Name equals proof generated"

$(PROOF_DIR)/attr_dob_proof.json: $(BUILD_DIR)/attr_equals_final.zkey | inputs
	@echo "🔧 Generating DOB equals proof..."
	$(SNARKJS) wtns calculate $(BUILD_DIR)/attr_equals_js/attr_equals.wasm $(PIPELINE_DIR)/.out/input.attr_dob_equals.json $(BUILD_DIR)/attr_equals_js/witness.wtns
	$(SNARKJS) groth16 prove $(BUILD_DIR)/attr_equals_final.zkey $(BUILD_DIR)/attr_equals_js/witness.wtns $(PROOF_DIR)/attr_dob_proof.json $(PROOF_DIR)/attr_dob_public.json
	@echo "✅ DOB equals proof generated"

$(PROOF_DIR)/income_gte_proof.json: $(BUILD_DIR)/income_check_final.zkey | inputs
	@echo "🔧 Generating income >= proof..."
	$(SNARKJS) wtns calculate $(BUILD_DIR)/income_check_js/income_check.wasm $(PIPELINE_DIR)/.out/input.income_gte.json $(BUILD_DIR)/income_check_js/witness.wtns
	$(SNARKJS) groth16 prove $(BUILD_DIR)/income_check_final.zkey $(BUILD_DIR)/income_check_js/witness.wtns $(PROOF_DIR)/income_gte_proof.json $(PROOF_DIR)/income_gte_public.json
	@echo "✅ Income >= proof generated"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(PROOF_DIR)
	@echo "🧹 Build artifacts cleaned"

# Clean everything including ptau
clean-all: clean
	rm -rf $(PTAU_DIR)
	@echo "🧹 All artifacts cleaned"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Compile all circuits and generate verifiers"
	@echo "  age-gte      - Compile age >= circuit"
	@echo "  age-lte      - Compile age <= circuit"
	@echo "  attr-equals  - Compile attribute equals circuit"
	@echo "  income-gte   - Compile income >= circuit"
	@echo "  inputs       - Generate input files from encrypted bundle"
	@echo "  proofs       - Generate all proofs"
	@echo "  verifiers    - Generate Solidity verifiers"
	@echo "  clean        - Clean build artifacts"
	@echo "  clean-all    - Clean everything including ptau"
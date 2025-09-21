#!/usr/bin/env bash
set -euo pipefail

# Example usage: ./scripts/prove_age.sh build/age_check_js/age_check.wasm build/age_check.r1cs input.json

WASM=$1
R1CS=$2
INPUT=$3
ZKEY=${4:-age_check_final.zkey}

node $WASM ../witness.wtns $INPUT witness.wtns
snarkjs groth16 setup $R1CS pot16_final.ptau $ZKEY
snarkjs zkey export verificationkey $ZKEY verification_key.json
snarkjs groth16 prove $ZKEY witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json

echo "Proof generated: proof.json"
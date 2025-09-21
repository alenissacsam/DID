# Identity Pipeline Helper

End-to-end helper for encrypted identity storage and ZK inputs generation.

What it does:
- Generates X25519 encryption keypair (tweetnacl)
- Builds Poseidon leaves & Merkle tree (circomlibjs + @zk-kit/incremental-merkle-tree)
- Encrypts a private bundle JSON with AEAD (ChaCha20-Poly1305 + AAD binding)
- Wraps CEK with NaCl box (X25519)
- Uploads encrypted bundle + public index to IPFS (web3.storage)
- Decrypts locally and generates Circom input files for all circuits

Setup:
```bash
cp ../../env.example .env
# Edit .env and set WEB3_STORAGE_TOKEN=your_token
npm install
```

Usage:
```bash
npm run run             # Generate, encrypt, upload
npm run decrypt         # Decrypt bundle to .out/bundle.decrypted.json
npm run generate-inputs # Create .out/input.*.json for circuits
npm run full-pipeline   # run + decrypt + generate-inputs
```

Outputs in `.out/`:
- bundle.enc, bundle.enc.meta.json, index.json
- bundle.decrypted.json
- input.age_gte.json, input.age_lte.json, input.attr_name_equals.json, input.attr_dob_equals.json, input.income_gte.json

See `docs/identity_storage_and_zk_pipeline.md` for the complete workflow.

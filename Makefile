include .env

# Default RPC selection: fall back to SEPOLIA_RPC_URL if RPC_URL is empty
ifeq ($(strip $(RPC_URL)),)
  ifneq ($(strip $(SEPOLIA_RPC_URL)),)
    RPC_URL := $(SEPOLIA_RPC_URL)
  endif
endif

# Default local RPC (used by *-local simulate targets)
LOCAL_RPC_URL ?= http://127.0.0.1:8545

# Warn if user mistakenly points to https://127.0.0.1 (Anvil is HTTP)
ifneq (,$(findstring https://127.0.0.1,$(RPC_URL)))
	$(warning RPC_URL uses https://127.0.0.1; use $(LOCAL_RPC_URL) instead)
endif

FORGE = forge

# Common flags
BUILD_FLAGS =
SIM_FLAGS = --rpc-url $(RPC_URL) -vvvv

# Conditional verification flags: if BLOCKSCOUT_VERIFIER is set, enable Blockscout verification
ifeq ($(strip $(BLOCKSCOUT_VERIFIER)),)
	VERIFY_FLAGS :=
else
	VERIFY_FLAGS := --verify --verifier blockscout --verifier-url $(BLOCKSCOUT_VERIFIER)
endif

BROADCAST_FLAGS = --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) $(VERIFY_FLAGS) --broadcast -vvvv

# Sepolia-specific flags (bypass RPC_URL from .env)
SIM_FLAGS_SEPOLIA = --rpc-url $(SEPOLIA_RPC_URL) -vvvv
BROADCAST_FLAGS_SEPOLIA = --rpc-url $(SEPOLIA_RPC_URL) --private-key $(PRIVATE_KEY) $(VERIFY_FLAGS) --broadcast -vvvv

.PHONY: build test test-gas test-fuzz clean \
        deploy-core simulate-core \
        deploy-complete simulate-complete \
        deploy-umbrella simulate-umbrella \
		deploy-zk simulate-zk \
	deploy-age-verifier deploy-age-max-verifier deploy-attr-verifier deploy-income-verifier \
	deploy-all-verifiers \
        deploy-accounts simulate-accounts \
        roles-bootstrap roles-grant-logger \
        identity-register identity-set-metadata \
		deploy-core-sepolia simulate-core-sepolia \
		deploy-zk-sepolia simulate-zk-sepolia \
		roles-bootstrap-sepolia identity-register-sepolia identity-set-metadata-sepolia \
		roles-grant-logger-sepolia simulate-roles-grant-logger-sepolia \
	zk-wire-existing \
	simulate-core-local simulate-zk-local \
	deploy-sepolia-all simulate-sepolia-all \
	deploy-sepolia-full simulate-sepolia-full show-zk-addresses \
	run-user-interactions \
	anvil help

# ------------------------------
# Build & Test
# ------------------------------
build:
	@$(FORGE) build $(BUILD_FLAGS)

test:
	@$(FORGE) test -vvv

test-gas:
	@$(FORGE) test --gas-report -vvv

test-fuzz:
	@$(FORGE) test --fork-url $(RPC_URL) -vvv

clean:
	@$(FORGE) clean

# ------------------------------
# Deploy: Core
# ------------------------------
deploy-core:
	@$(FORGE) script script/deploy/DeployAll.s.sol:DeployAll $(BROADCAST_FLAGS)

simulate-core:
	@$(FORGE) script script/deploy/DeployAll.s.sol:DeployAll $(SIM_FLAGS)

simulate-core-local:
	@RPC_URL=$(LOCAL_RPC_URL) $(FORGE) script script/deploy/DeployAll.s.sol:DeployAll $(SIM_FLAGS)

# ------------------------------
# Deploy: Complete stack (core + managers + orgs + guardian/anchor + governance)
# ------------------------------
deploy-complete:
	@$(FORGE) script script/deploy/DeployComplete.s.sol:DeployComplete $(BROADCAST_FLAGS)

simulate-complete:
	@$(FORGE) script script/deploy/DeployComplete.s.sol:DeployComplete $(SIM_FLAGS)

# ------------------------------
# Deploy: Umbrella (core + common modules) — convenient for local/anvil
# ------------------------------
deploy-umbrella:
	@$(FORGE) script script/deploy/DeployUmbrella.s.sol:DeployUmbrella $(BROADCAST_FLAGS)

simulate-umbrella:
	@$(FORGE) script script/deploy/DeployUmbrella.s.sol:DeployUmbrella $(SIM_FLAGS)

# ------------------------------
# Deploy: ZK Manager & Verifiers wiring
# Notes: Verifier and manager addresses are OPTIONAL. If not provided, the
#        script will auto-deploy verifiers and auto-resolve recent deployments
#        (ZKProofManager/managers/anchor) via DevOpsTools. Optional overrides:
#        AGE_VERIFIER_ADDR, ATTR_VERIFIER_ADDR, INCOME_VERIFIER_ADDR, AGE_MAX_VERIFIER_ADDR,
#        ZK_ROOT, ANCHOR_ADDRESS, AADHAAR_ADDRESS, INCOME_ADDRESS, OFFLINE_ADDRESS
# ------------------------------
deploy-zk:
	@$(FORGE) script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK $(BROADCAST_FLAGS)

simulate-zk:
	@$(FORGE) script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK $(SIM_FLAGS)

simulate-zk-local:
	@RPC_URL=$(LOCAL_RPC_URL) SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK $(SIM_FLAGS)
# ------------------------------
# Sepolia-specific one-off targets (explicitly use SEPOLIA_RPC_URL)
# ------------------------------
deploy-core-sepolia:
	@$(FORGE) script script/deploy/DeployAll.s.sol:DeployAll $(BROADCAST_FLAGS_SEPOLIA)

simulate-core-sepolia:
	@$(FORGE) script script/deploy/DeployAll.s.sol:DeployAll $(SIM_FLAGS_SEPOLIA)

deploy-zk-sepolia:
	@SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK $(BROADCAST_FLAGS_SEPOLIA)

simulate-zk-sepolia:
	@SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK $(SIM_FLAGS_SEPOLIA)

roles-bootstrap-sepolia:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run deploy-core-sepolia first."; exit 2; fi; \
	TS_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" TrustScore); \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$TS_ADDR" ] || [ "$$TS_ADDR" = "null" ] || [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then \
		echo "ERROR: Could not resolve TrustScore/UserIdentityRegistry addresses from $$REG_FILE"; exit 2; \
	fi; \
	echo "Using TrustScore=$$TS_ADDR, Registry=$$REG_ADDR"; \
	SKIP_DEVOPS_LOOKUP=1 TRUST_SCORE_ADDRESS=$$TS_ADDR REGISTRY_ADDRESS=$$REG_ADDR $(FORGE) script script/interactions/BootstrapRoles.s.sol:BootstrapRoles $(BROADCAST_FLAGS_SEPOLIA)

roles-grant-logger-sepolia:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run deploy-core-sepolia first."; exit 2; fi; \
	LOG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" VerificationLogger); \
	TS_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" TrustScore); \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$LOG_ADDR" ] || [ "$$LOG_ADDR" = "null" ]; then echo "ERROR: Could not resolve VerificationLogger address from $$REG_FILE"; exit 2; fi; \
	if [ -z "$$TS_ADDR" ] || [ "$$TS_ADDR" = "null" ]; then echo "ERROR: Could not resolve TrustScore address from $$REG_FILE"; exit 2; fi; \
	if [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then echo "ERROR: Could not resolve UserIdentityRegistry address from $$REG_FILE"; exit 2; fi; \
	echo "Granting LOGGER_ROLE on $$LOG_ADDR to TrustScore=$$TS_ADDR and Registry=$$REG_ADDR"; \
	SKIP_DEVOPS_LOOKUP=1 LOGGER_ADDRESS=$$LOG_ADDR GRANTEE_ADDRESS=$$TS_ADDR $(FORGE) script script/interactions/GrantLoggerRole.s.sol:GrantLoggerRole $(BROADCAST_FLAGS_SEPOLIA) && \
	SKIP_DEVOPS_LOOKUP=1 LOGGER_ADDRESS=$$LOG_ADDR GRANTEE_ADDRESS=$$REG_ADDR $(FORGE) script script/interactions/GrantLoggerRole.s.sol:GrantLoggerRole $(BROADCAST_FLAGS_SEPOLIA)

simulate-roles-grant-logger-sepolia:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run simulate-core-sepolia or deploy-core-sepolia first."; exit 2; fi; \
	LOG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" VerificationLogger); \
	TS_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" TrustScore); \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$LOG_ADDR" ] || [ "$$LOG_ADDR" = "null" ] || [ -z "$$TS_ADDR" ] || [ "$$TS_ADDR" = "null" ] || [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then \
		echo "ERROR: Could not resolve one or more addresses from $$REG_FILE"; exit 2; \
	fi; \
	echo "[SIM] Would grant LOGGER_ROLE on $$LOG_ADDR to $$TS_ADDR and $$REG_ADDR"; \
	SKIP_DEVOPS_LOOKUP=1 LOGGER_ADDRESS=$$LOG_ADDR GRANTEE_ADDRESS=$$TS_ADDR $(FORGE) script script/interactions/GrantLoggerRole.s.sol:GrantLoggerRole $(SIM_FLAGS_SEPOLIA) && \
	SKIP_DEVOPS_LOOKUP=1 LOGGER_ADDRESS=$$LOG_ADDR GRANTEE_ADDRESS=$$REG_ADDR $(FORGE) script script/interactions/GrantLoggerRole.s.sol:GrantLoggerRole $(SIM_FLAGS_SEPOLIA)

simulate-roles-bootstrap-sepolia:
	@SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/interactions/BootstrapRoles.s.sol:BootstrapRoles $(SIM_FLAGS_SEPOLIA)

identity-register-sepolia:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run deploy-core-sepolia first."; exit 2; fi; \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then \
		echo "ERROR: Could not resolve UserIdentityRegistry address from $$REG_FILE"; exit 2; \
	fi; \
	echo "Using Registry=$$REG_ADDR"; \
	# If USER_ADDRESS isn't explicitly provided, register the broadcaster (msg.sender)
	if [ -z "$$USER_ADDRESS" ]; then unset USER_ADDRESS; fi; \
	SKIP_DEVOPS_LOOKUP=1 REGISTRY_ADDRESS=$$REG_ADDR $(FORGE) script script/interactions/RegisterIdentity.s.sol:RegisterIdentity $(BROADCAST_FLAGS_SEPOLIA)

identity-set-metadata-sepolia:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run deploy-core-sepolia first."; exit 2; fi; \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then \
		echo "ERROR: Could not resolve UserIdentityRegistry address from $$REG_FILE"; exit 2; \
	fi; \
	echo "Using Registry=$$REG_ADDR"; \
	if [ -z "$$IDENTITY_METADATA_URI" ]; then IDENTITY_METADATA_URI=ipfs://example-demo; fi; \
	# If USER_ADDRESS isn't explicitly provided, target the broadcaster (msg.sender)
	if [ -z "$$USER_ADDRESS" ]; then unset USER_ADDRESS; fi; \
	SKIP_DEVOPS_LOOKUP=1 REGISTRY_ADDRESS=$$REG_ADDR IDENTITY_METADATA_URI=$$IDENTITY_METADATA_URI $(FORGE) script script/interactions/SetIdentityMetadata.s.sol:SetIdentityMetadata $(BROADCAST_FLAGS_SEPOLIA)


# Wire existing ZKPM with pre-deployed verifiers (alternative script)
zk-wire-existing:
	@$(FORGE) script script/zk/DeployZK.s.sol:DeployZK $(BROADCAST_FLAGS)

# ------------------------------
# Deploy: Individual verifiers (Groth16)
# ------------------------------
deploy-age-verifier:
	@$(FORGE) script script/zk/DeployAgeVerifier.s.sol:DeployAgeVerifier $(BROADCAST_FLAGS)

deploy-age-max-verifier:
	@$(FORGE) script script/zk/DeployAgeMaxVerifier.s.sol:DeployAgeMaxVerifier $(BROADCAST_FLAGS)

deploy-attr-verifier:
	@$(FORGE) script script/zk/DeployAttrVerifier.s.sol:DeployAttrVerifier $(BROADCAST_FLAGS)

deploy-income-verifier:
	@$(FORGE) script script/zk/DeployIncomeVerifier.s.sol:DeployIncomeVerifier $(BROADCAST_FLAGS)

# Deploy all four verifiers in sequence
deploy-all-verifiers:
	@$(MAKE) --no-print-directory deploy-age-verifier
	@$(MAKE) --no-print-directory deploy-attr-verifier
	@$(MAKE) --no-print-directory deploy-income-verifier
	@$(MAKE) --no-print-directory deploy-age-max-verifier

# ------------------------------
# Deploy: ERC-4337 Accounts factory & bundler wiring
FORGE=forge

.PHONY: build test clean help

build:
	@$(FORGE) build

test:
	@$(FORGE) test -vvv

clean:
	@$(FORGE) clean

help:
	@echo "Minimal Makefile." && \
	echo "Targets: build test clean" && \
	echo "All deployment & interaction scripts removed (2025-09-25)."
	$(MAKE) --no-print-directory identity-register-sepolia || true && \
	echo "[6/6] Setting identity metadata for the deployer (optional)..." && \
	$(MAKE) --no-print-directory identity-set-metadata-sepolia || true && \
	echo "Done. See broadcast/zk-addresses.$(shell cast chain-id).json for ZK addresses."

simulate-sepolia-full:
	@if [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "ERROR: SEPOLIA_RPC_URL is empty. Set SEPOLIA_RPC_URL in your env."; exit 2; fi
	@echo "[1/5] Simulating core..." && \
	$(MAKE) --no-print-directory simulate-core-sepolia && \
	echo "[2/5] Simulating ZK wiring..." && \
	$(MAKE) --no-print-directory simulate-zk-sepolia && \
	echo "[3/5] Simulating roles bootstrap..." && \
	$(MAKE) --no-print-directory simulate-roles-bootstrap-sepolia || true && \
	echo "[4/5] Simulating logger role grants..." && \
	$(MAKE) --no-print-directory simulate-roles-grant-logger-sepolia || true && \
	echo "[5/5] Simulating identity steps..." && \
	$(MAKE) --no-print-directory simulate-identity-register-sepolia || true && \
	$(MAKE) --no-print-directory simulate-identity-set-metadata-sepolia || true && \
	echo "Note: Simulations do not persist; for addresses see deploy broadcast runs."

# Sepolia-specific simulation helpers for identity
simulate-identity-register-sepolia:
	@SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/interactions/RegisterIdentity.s.sol:RegisterIdentity $(SIM_FLAGS_SEPOLIA)
run-user-interactions:
	@REG_FILE="broadcast/DeployAll.s.sol/11155111/run-latest.json"; \
	if [ ! -f "$$REG_FILE" ]; then echo "ERROR: $$REG_FILE not found. Run deploy-core-sepolia first."; exit 2; fi; \
	REG_ADDR=$$(python3 tools/parse_broadcast.py "$$REG_FILE" UserIdentityRegistry); \
	if [ -z "$$REG_ADDR" ] || [ "$$REG_ADDR" = "null" ]; then echo "ERROR: Could not resolve UserIdentityRegistry address from $$REG_FILE"; exit 2; fi; \
	echo "Running aggregated user interactions on Registry=$$REG_ADDR"; \
	SKIP_DEVOPS_LOOKUP=1 REGISTRY_ADDRESS=$$REG_ADDR $(FORGE) script script/interactions/AllUserInteractions.s.sol:AllUserInteractions $(BROADCAST_FLAGS_SEPOLIA)

simulate-identity-set-metadata-sepolia:
	@SKIP_DEVOPS_LOOKUP=1 $(FORGE) script script/interactions/SetIdentityMetadata.s.sol:SetIdentityMetadata $(SIM_FLAGS_SEPOLIA)

# Convenience: display the last generated zk addresses JSON for current chain
show-zk-addresses:
	@CID=$$(cast chain-id 2>/dev/null || echo sepolia); \
	FILE=broadcast/zk-addresses.$$CID.json; \
	if [ -f "$$FILE" ]; then echo "Showing $$FILE"; cat "$$FILE"; else echo "No $$FILE found. Run deploy-zk or deploy-sepolia-* first."; fi

# ------------------------------
# Local Anvil helper (run in a separate shell)
# ------------------------------
anvil:
	@echo "Starting anvil on $(LOCAL_RPC_URL) (Ctrl+C to stop)..." && anvil -p 8545

help:
	@echo "Available targets:" && \
	echo "  build, test, test-gas, test-fuzz, clean" && \
	echo "  deploy-core | simulate-core | simulate-core-local" && \
	echo "  deploy-complete | simulate-complete" && \
	echo "  deploy-umbrella | simulate-umbrella" && \
	echo "  deploy-zk | simulate-zk | simulate-zk-local | zk-wire-existing" && \
	echo "  deploy-accounts | simulate-accounts" && \
	echo "  roles-bootstrap | roles-grant-logger" && \
	echo "  identity-register | identity-set-metadata" && \
	echo "  deploy-sepolia-all | simulate-sepolia-all" && \
	echo "  deploy-sepolia-full | simulate-sepolia-full | run-user-interactions" && \
	echo "Environment vars: RPC_URL, SEPOLIA_RPC_URL, PRIVATE_KEY (broadcast), ENTRYPOINT_ADDRESS (accounts). Others auto-resolve; see env.example."

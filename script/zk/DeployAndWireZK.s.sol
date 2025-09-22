// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {ZKProofManager} from "../../src/verification/ZKProofManager.sol";

interface ISetZkProofManager {
    function setZkProofManager(address manager) external;
}

/// Usage:
///  forge script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
///
/// Env vars:
///  - DEPLOY_ZKPM = true|false (default true)
///  - ZKPM_ADDRESS = existing ZKProofManager (if DEPLOY_ZKPM=false)
///  - AGE_VERIFIER_ADDR, ATTR_VERIFIER_ADDR, INCOME_VERIFIER_ADDR, AGE_MAX_VERIFIER_ADDR
///  - ZK_ROOT (optional) hex bytes32 to anchor
///  - ANCHOR_ADDRESS (optional) if you want to grant ROOT_MANAGER_ROLE to GlobalCredentialAnchor
///  - AADHAAR_ADDRESS, INCOME_ADDRESS, OFFLINE_ADDRESS (optional) to auto-wire their setZkProofManager
///
/// This script will also attempt to auto-wire the ZKProofManager into the deployed
/// Aadhaar/Income/Offline managers and GlobalCredentialAnchor using DevOpsTools to
/// locate the most recent deployments. Calls are wrapped in try/catch so missing
/// roles or absent deployments won't break the run.
contract DeployAndWireZK is Script {
    function run() external {
        bool deploy = vm.envOr("DEPLOY_ZKPM", true);
        address zkpmAddr = vm.envOr("ZKPM_ADDRESS", address(0));
        address ageVerifier = vm.envAddress("AGE_VERIFIER_ADDR");
        address attrVerifier = vm.envAddress("ATTR_VERIFIER_ADDR");
        address incomeVerifier = vm.envAddress("INCOME_VERIFIER_ADDR");
        address ageMaxVerifier = vm.envAddress("AGE_MAX_VERIFIER_ADDR");

        bytes32 rootToAnchor = vm.envOr("ZK_ROOT", bytes32(0));
        address anchorAddrEnv = vm.envOr("ANCHOR_ADDRESS", address(0));

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        ZKProofManager zkpm;
        if (deploy) {
            zkpm = new ZKProofManager();
            console.log("ZKProofManager deployed:", address(zkpm));
        } else {
            require(zkpmAddr != address(0), "ZKPM_ADDRESS required");
            zkpm = ZKProofManager(zkpmAddr);
            console.log("ZKProofManager (existing):", address(zkpm));
        }

        // Register proof types: 0=Age>=, 1=Attr==, 2=Income>=, 3=Age<=
        // Note: names are free-form; we standardize on: age_gte, attr_equals, income_gte, age_lte
        _ensureProofType(zkpm, "age_gte", ageVerifier);
        _ensureProofType(zkpm, "attr_equals", attrVerifier);
        _ensureProofType(zkpm, "income_gte", incomeVerifier);
        _ensureProofType(zkpm, "age_lte", ageMaxVerifier);

        if (rootToAnchor != bytes32(0)) {
            try zkpm.anchorRoot(rootToAnchor) {
                console.log("Anchored root on ZKProofManager");
            } catch {
                console.log("Failed to anchor root (missing role?)");
            }
        }

        // Auto-wire: setZkProofManager on deployed managers (best-effort)
        address aadhaar = vm.envOr("AADHAAR_ADDRESS", address(0));
        address income = vm.envOr("INCOME_ADDRESS", address(0));
        address offline = vm.envOr("OFFLINE_ADDRESS", address(0));
        address anchor = anchorAddrEnv;

        if (aadhaar != address(0)) {
            try ISetZkProofManager(aadhaar).setZkProofManager(address(zkpm)) {
                console.log("Wired AadhaarVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Aadhaar (missing admin role?)");
            }
        }
        if (income != address(0)) {
            try ISetZkProofManager(income).setZkProofManager(address(zkpm)) {
                console.log("Wired IncomeVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Income (missing admin role?)");
            }
        }
        if (offline != address(0)) {
            try ISetZkProofManager(offline).setZkProofManager(address(zkpm)) {
                console.log("Wired OfflineVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Offline (missing admin role?)");
            }
        }

        // Grant ROOT_MANAGER_ROLE to GlobalCredentialAnchor so it can sync roots
        if (anchor != address(0)) {
            try zkpm.grantRole(zkpm.ROOT_MANAGER_ROLE(), anchor) {
                console.log(
                    "Granted ROOT_MANAGER_ROLE to GlobalCredentialAnchor:",
                    anchor
                );
            } catch {
                console.log(
                    "Failed to grant ROOT_MANAGER_ROLE to Anchor (need admin role)"
                );
            }
            // Also attempt to set ZKPM on the anchor
            try ISetZkProofManager(anchor).setZkProofManager(address(zkpm)) {
                console.log("Wired GlobalCredentialAnchor -> ZKPM");
            } catch {
                console.log(
                    "Failed to wire Anchor (missing ANCHOR_ADMIN_ROLE?)"
                );
            }
        }

        vm.stopBroadcast();
    }

    function _ensureProofType(
        ZKProofManager zkpm,
        string memory name,
        address verifier
    ) internal {
        try zkpm.resolveTypeId(name) returns (bool found, uint256 typeId) {
            if (found) {
                try zkpm.getProofType(typeId) returns (
                    string memory,
                    address currentVerifier,
                    bool isActive
                ) {
                    if (currentVerifier != verifier) {
                        try zkpm.updateProofType(typeId, verifier, isActive) {
                            console.log("Updated proof type", typeId, verifier);
                        } catch {
                            console.log(
                                "Failed to update proof type (missing role?)"
                            );
                        }
                    } else {
                        console.log("Proof type already up-to-date:", name);
                    }
                } catch {
                    console.log("Could not fetch existing proof type info");
                }
            } else {
                try zkpm.addProofType(name, verifier) {
                    console.log("Added proof type:", name, verifier);
                } catch {
                    console.log(
                        "Failed to add proof type (missing ROOT_MANAGER_ROLE?)"
                    );
                }
            }
        } catch {
            // If resolve fails (shouldn't), fall back to adding
            try zkpm.addProofType(name, verifier) {
                console.log("Added proof type (fallback):", name, verifier);
            } catch {
                console.log(
                    "Failed to add proof type (fallback; missing role?)"
                );
            }
        }
    }
}

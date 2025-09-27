// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DeployLib} from "./DeployLib.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {GuardianManager} from "../../src/advanced_features/GuardianManager.sol";
import {GlobalCredentialAnchor} from "../../src/privacy_cross-chain/GlobalCredentialAnchor.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";
import {OfflineVerificationManager} from "../../src/verification/OfflineVerificationManager.sol";
import {MobileVerificationInterface} from "../../src/verification/MobileVerificationInterface.sol";
import {AadhaarVerificationManager} from "../../src/verification/AadhaarVerificationManager.sol";
import {IncomeVerificationManager} from "../../src/verification/IncomeVerificationManager.sol";
import {FaceVerificationManager} from "../../src/verification/FaceVerificationManager.sol";
import {DisputeResolution} from "../../src/governance/DisputeResolution.sol";
import {IdentityAccountFactory} from "../../src/advanced_features/IdentityAccountFactory.sol";
import {ZKProofManager} from "../../src/verification/ZKProofManager.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";

import {Groth16Verifier as AgeVerifierContract} from "../../tools/zk-circuits/build/AgeVerifier.sol";
import {Groth16Verifier as AgeMaxVerifierContract} from "../../tools/zk-circuits/build/AgeMaxVerifier.sol";
import {Groth16Verifier as AttrVerifierContract} from "../../tools/zk-circuits/build/AttrVerifier.sol";
import {Groth16Verifier as IncomeVerifierContract} from "../../tools/zk-circuits/build/IncomeVerifier.sol";

/// @notice Deploys the entire DID stack, including core registries, verification managers,
///         account factory and ZK proof manager, then writes a JSON artifact consumable by the frontend.
///
/// Usage:
///   forge script script/deploy/DeployFullStackWithConfig.s.sol:DeployFullStackWithConfig \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
///
/// Env vars:
///   NETWORK_NAME                Optional friendly network label (default: derived from chainId)
///   DEPLOY_OUTPUT_PATH          File path for deployment artifact (default: deployments/deployment.<chainId>.json)
///   FRONTEND_CONFIG_PATH        Optional additional path (e.g. tools/frontend/public/config/deployment.json)
///   ENTRYPOINT_ADDRESS          Required for IdentityAccountFactory deployment
///   BUNDLER_ADDRESS             Optional bundler service address (defaults to deployer)
///   MAX_ACCOUNTS_PER_USER       Optional cap for factory (default: 1)
///   DEPLOY_ZKPM                 Whether to deploy a new ZKProofManager (default: true)
///   ZKPM_ADDRESS                Existing manager address when DEPLOY_ZKPM=false
///   ZK_ROOT                     Optional root to anchor immediately
///   SKIP_DEVOPS_LOOKUP          Skip DevOpsTools lookups when true
contract DeployFullStackWithConfig is Script {
    using DeployLib for *;

    struct ZkArtifacts {
        ZKProofManager manager;
        address ageGteVerifier;
        address ageLteVerifier;
        address attrEqualsVerifier;
        address incomeGteVerifier;
    }

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        string memory networkName = vm.envOr("NETWORK_NAME", string(""));
        if (bytes(networkName).length == 0) {
            networkName = _defaultNetworkName(block.chainid);
        }

        string memory defaultOutput = string.concat(
            "deployments/deployment.",
            vm.toString(block.chainid),
            ".json"
        );
        string memory outputPath = vm.envOr(
            "DEPLOY_OUTPUT_PATH",
            defaultOutput
        );
        string memory frontendPath = vm.envOr(
            "FRONTEND_CONFIG_PATH",
            string("")
        );

        vm.startBroadcast(pk);

        // Core stack
        DeployLib.Core memory core = DeployLib.deployCore();
        DeployLib.VerificationStack memory verifiers = DeployLib
            .deployVerificationStack(
                address(core.logger),
                address(core.registry),
                address(core.trust)
            );
        (
            OfflineVerificationManager offline,
            MobileVerificationInterface mobile
        ) = DeployLib.deployOfflineMobile(admin);
        CertificateManager cert = DeployLib.deployOrganizations(
            address(core.logger),
            address(core.registry),
            address(core.trust)
        );
        (
            GuardianManager guardian,
            GlobalCredentialAnchor anchor,
            ZkKeyRegistry zkRegistry
        ) = DeployLib.deployGuardianAnchor(
                address(core.logger),
                address(core.registry),
                address(core.trust)
            );
        DisputeResolution dispute = DeployLib.deployGovernance(
            address(core.logger),
            address(core.trust)
        );

        // Identity factory + bundler wiring
        address entryPoint = vm.envOr(
            "ENTRYPOINT_ADDRESS",
            _defaultEntryPoint(block.chainid)
        );
        require(
            entryPoint != address(0),
            "ENTRYPOINT_ADDRESS required for this network"
        );
        address bundler = vm.envOr("BUNDLER_ADDRESS", admin);
        uint256 maxAccountsPerUser = vm.envOr(
            "MAX_ACCOUNTS_PER_USER",
            uint256(1)
        );
        IdentityAccountFactory factory = new IdentityAccountFactory(
            entryPoint,
            address(core.logger),
            address(core.trust),
            maxAccountsPerUser
        );
        factory.setBundler(bundler);
        factory.grantRole(keccak256("CREATOR_ROLE"), admin);

        // Role wiring similar to DeployComplete
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        bytes32 SCORE_MANAGER_ROLE = keccak256("SCORE_MANAGER_ROLE");
        VerificationLogger(address(core.logger)).grantRole(
            LOGGER_ROLE,
            address(core.trust)
        );
        VerificationLogger(address(core.logger)).grantRole(
            LOGGER_ROLE,
            address(core.registry)
        );
        TrustScore(address(core.trust)).grantRole(
            SCORE_MANAGER_ROLE,
            address(core.registry)
        );
        cert.grantRole(keccak256("ISSUER_ROLE"), admin);

        // Deploy or resolve ZK stack and wire
        ZkArtifacts memory zk = _deployZkStack(
            admin,
            address(anchor),
            address(verifiers.aadhaar),
            address(verifiers.income),
            address(offline)
        );

        // Persist JSON artifact
        string memory root = "deployment";

        vm.serializeUint(root, "network.chainId", block.chainid);
        vm.serializeString(root, "network.name", networkName);
        vm.serializeAddress(root, "deployer.address", admin);
        vm.serializeAddress(
            root,
            "core.verificationLogger",
            address(core.logger)
        );
        vm.serializeAddress(root, "core.trustScore", address(core.trust));
        vm.serializeAddress(
            root,
            "core.userIdentityRegistry",
            address(core.registry)
        );

        vm.serializeAddress(root, "verification.face", address(verifiers.face));
        vm.serializeAddress(
            root,
            "verification.aadhaar",
            address(verifiers.aadhaar)
        );
        vm.serializeAddress(
            root,
            "verification.income",
            address(verifiers.income)
        );
        vm.serializeAddress(root, "verification.offline", address(offline));
        vm.serializeAddress(root, "verification.mobile", address(mobile));

        vm.serializeAddress(
            root,
            "organizations.certificateManager",
            address(cert)
        );
        vm.serializeAddress(
            root,
            "identity.guardianManager",
            address(guardian)
        );
        vm.serializeAddress(
            root,
            "identity.globalCredentialAnchor",
            address(anchor)
        );
        vm.serializeAddress(
            root,
            "identity.zkKeyRegistry",
            address(zkRegistry)
        );
        vm.serializeAddress(
            root,
            "governance.disputeResolution",
            address(dispute)
        );
        vm.serializeAddress(root, "identity.accountFactory", address(factory));
        vm.serializeAddress(root, "identity.entryPoint", entryPoint);
        vm.serializeAddress(root, "identity.bundler", bundler);

        vm.serializeAddress(root, "zk.manager", address(zk.manager));
        vm.serializeAddress(root, "zk.verifiers.age_gte", zk.ageGteVerifier);
        vm.serializeAddress(root, "zk.verifiers.age_lte", zk.ageLteVerifier);
        vm.serializeAddress(
            root,
            "zk.verifiers.attr_equals",
            zk.attrEqualsVerifier
        );
        vm.serializeAddress(
            root,
            "zk.verifiers.income_gte",
            zk.incomeGteVerifier
        );

        vm.serializeString(
            root,
            "meta.generatedAt",
            vm.toString(block.timestamp)
        );
        vm.serializeString(
            root,
            "meta.note",
            "Auto-generated by DeployFullStackWithConfig"
        );

        vm.writeJson(root, outputPath);
        console.log("Deployment artifact written to:", outputPath);
        if (bytes(frontendPath).length > 0) {
            vm.writeJson(root, frontendPath);
            console.log("Frontend config mirrored to:", frontendPath);
        }

        vm.stopBroadcast();
    }

    function _deployZkStack(
        address admin,
        address anchor,
        address aadhaar,
        address income,
        address offline
    ) internal returns (ZkArtifacts memory zk) {
        bool deploy = vm.envOr("DEPLOY_ZKPM", true);
        bool skipLookup = vm.envOr("SKIP_DEVOPS_LOOKUP", false);
        address zkpmAddr = vm.envOr("ZKPM_ADDRESS", address(0));
        bytes32 rootToAnchor = vm.envOr("ZK_ROOT", bytes32(0));

        if (!deploy) {
            if (zkpmAddr == address(0) && !skipLookup) {
                zkpmAddr = DevOpsTools.get_most_recent_deployment(
                    "ZKProofManager",
                    block.chainid
                );
            }
            require(zkpmAddr != address(0), "ZKProofManager not found");
            zk.manager = ZKProofManager(zkpmAddr);
            console.log("Reusing ZKProofManager:", zkpmAddr);
        } else {
            zk.manager = new ZKProofManager();
            console.log("ZKProofManager deployed:", address(zk.manager));
        }

        zk.ageGteVerifier = _deployVerifier(
            vm.envOr("AGE_VERIFIER_ADDR", address(0)),
            "age_gte"
        );
        zk.attrEqualsVerifier = _deployVerifier(
            vm.envOr("ATTR_VERIFIER_ADDR", address(0)),
            "attr_equals"
        );
        zk.incomeGteVerifier = _deployVerifier(
            vm.envOr("INCOME_VERIFIER_ADDR", address(0)),
            "income_gte"
        );
        zk.ageLteVerifier = _deployVerifier(
            vm.envOr("AGE_MAX_VERIFIER_ADDR", address(0)),
            "age_lte"
        );

        _ensureProofType(zk.manager, "age_gte", zk.ageGteVerifier);
        _ensureProofType(zk.manager, "attr_equals", zk.attrEqualsVerifier);
        _ensureProofType(zk.manager, "income_gte", zk.incomeGteVerifier);
        _ensureProofType(zk.manager, "age_lte", zk.ageLteVerifier);

        if (rootToAnchor != bytes32(0)) {
            try zk.manager.anchorRoot(rootToAnchor) {
                console.log("Anchored root on ZKProofManager");
            } catch {
                console.log("Failed to anchor root (missing role?)");
            }
        }

        _wireZkManager(zk.manager, anchor, aadhaar, income, offline, admin);
    }

    function _deployVerifier(
        address existing,
        string memory label
    ) internal returns (address deployed) {
        if (existing != address(0)) {
            console.log("Reusing", label, existing);
            return existing;
        }
        if (_eq(label, "age_gte")) {
            deployed = address(new AgeVerifierContract());
        } else if (_eq(label, "age_lte")) {
            deployed = address(new AgeMaxVerifierContract());
        } else if (_eq(label, "attr_equals")) {
            deployed = address(new AttrVerifierContract());
        } else if (_eq(label, "income_gte")) {
            deployed = address(new IncomeVerifierContract());
        } else {
            revert("unknown verifier label");
        }
        console.log("Deployed Groth16 verifier", label, deployed);
    }

    function _wireZkManager(
        ZKProofManager manager,
        address anchor,
        address aadhaar,
        address income,
        address offline,
        address admin
    ) internal {
        if (aadhaar != address(0)) {
            try
                AadhaarVerificationManager(aadhaar).setZkProofManager(
                    address(manager)
                )
            {
                console.log("Wired AadhaarVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Aadhaar (missing admin role?)");
            }
        }
        if (income != address(0)) {
            try
                IncomeVerificationManager(income).setZkProofManager(
                    address(manager)
                )
            {
                console.log("Wired IncomeVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Income (missing admin role?)");
            }
        }
        if (offline != address(0)) {
            try
                OfflineVerificationManager(offline).setZkProofManager(
                    address(manager)
                )
            {
                console.log("Wired OfflineVerificationManager -> ZKPM");
            } catch {
                console.log("Failed to wire Offline (missing admin role?)");
            }
        }
        if (anchor != address(0)) {
            try manager.grantRole(manager.ROOT_MANAGER_ROLE(), anchor) {
                console.log(
                    "Granted ROOT_MANAGER_ROLE to GlobalCredentialAnchor"
                );
            } catch {
                console.log(
                    "Failed to grant ROOT_MANAGER_ROLE to anchor (need admin role)"
                );
            }
            try
                GlobalCredentialAnchor(anchor).setZkProofManager(
                    address(manager)
                )
            {
                console.log("Wired GlobalCredentialAnchor -> ZKPM");
            } catch {
                console.log(
                    "Failed to wire anchor (missing anchor admin role?)"
                );
            }
        }
    }

    function _ensureProofType(
        ZKProofManager manager,
        string memory name,
        address verifier
    ) internal {
        try manager.resolveTypeId(name) returns (bool found, uint256 typeId) {
            if (found) {
                try manager.getProofType(typeId) returns (
                    string memory,
                    address currentVerifier,
                    bool isActive
                ) {
                    if (currentVerifier != verifier) {
                        try
                            manager.updateProofType(typeId, verifier, isActive)
                        {
                            console.log("Updated proof type", typeId, verifier);
                        } catch {
                            console.log(
                                "Failed to update proof type (missing role?)"
                            );
                        }
                    }
                } catch {
                    console.log("Could not fetch existing proof type info");
                }
            } else {
                try manager.addProofType(name, verifier) {
                    console.log("Added proof type", name, verifier);
                } catch {
                    console.log(
                        "Failed to add proof type (missing ROOT_MANAGER_ROLE?)"
                    );
                }
            }
        } catch {
            try manager.addProofType(name, verifier) {
                console.log("Added proof type (fallback)", name, verifier);
            } catch {
                console.log(
                    "Failed to add proof type (fallback; missing role?)"
                );
            }
        }
    }

    function _defaultNetworkName(
        uint256 chainId
    ) internal pure returns (string memory) {
        if (chainId == 1) return "ethereum";
        if (chainId == 5) return "goerli";
        if (chainId == 10) return "optimism";
        if (chainId == 137) return "polygon";
        if (chainId == 11155111) return "sepolia";
        if (chainId == 80002) return "amoy";
        return "unknown";
    }

    function _defaultEntryPoint(
        uint256 chainId
    ) internal pure returns (address) {
        if (chainId == 11155111) {
            return address(0x0000000071727de22e5E9D8bAF0eDAcb0f3F0EAB);
        }
        return address(0);
    }

    function _eq(
        string memory a,
        string memory b
    ) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}

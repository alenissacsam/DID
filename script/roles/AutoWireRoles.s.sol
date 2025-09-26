// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";

contract AutoWireRoles is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        vm.startBroadcast(pk);

        address logger = DevOpsTools.get_most_recent_deployment(
            "VerificationLogger",
            block.chainid
        );
        address trust = DevOpsTools.get_most_recent_deployment(
            "TrustScore",
            block.chainid
        );
        address registry = DevOpsTools.get_most_recent_deployment(
            "UserIdentityRegistry",
            block.chainid
        );

        // Wire logger roles
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        VerificationLogger(logger).grantRole(LOGGER_ROLE, trust);
        VerificationLogger(logger).grantRole(LOGGER_ROLE, registry);
        console.log("Granted LOGGER_ROLE to Trust & Registry");

        // Trust score manager role -> registry
        bytes32 SCORE_MANAGER_ROLE = keccak256("SCORE_MANAGER_ROLE");
        TrustScore(trust).grantRole(SCORE_MANAGER_ROLE, registry);
        console.log("Granted SCORE_MANAGER_ROLE to Registry");

        // Give ourselves org roles for demos
        address certAddr = DevOpsTools.get_most_recent_deployment(
            "CertificateManager",
            block.chainid
        );

        if (certAddr != address(0)) {
            CertificateManager(certAddr).grantRole(
                keccak256("ISSUER_ROLE"),
                admin
            );
            console.log("Granted ISSUER_ROLE on CertificateManager to admin");
        }
        // Recognition system removed; no badge roles to wire.

        vm.stopBroadcast();
    }
}

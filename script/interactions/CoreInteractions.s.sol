// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";

contract CoreInteractions is Script {
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

        console.log("Logger:", logger);
        console.log("TrustScore:", trust);
        console.log("Registry:", registry);

        // Grant roles: LOGGER_ROLE to TrustScore and Registry; SCORE_MANAGER_ROLE to Registry
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        VerificationLogger(logger).grantRole(LOGGER_ROLE, trust);
        VerificationLogger(logger).grantRole(LOGGER_ROLE, registry);
        console.log("Granted LOGGER_ROLE to Trust & Registry");

        bytes32 SCORE_MANAGER_ROLE = keccak256("SCORE_MANAGER_ROLE");
        TrustScore(trust).grantRole(SCORE_MANAGER_ROLE, registry);
        console.log("Granted SCORE_MANAGER_ROLE to Registry");

        // Register the admin (as demo) and set metadata
        bytes32 commitment = keccak256(abi.encodePacked("LOCAL_DEV", admin));
        UserIdentityRegistry(registry).registerIdentity(admin, commitment);
        UserIdentityRegistry(registry).setMetadataURI(
            admin,
            "ipfs://demo-metadata"
        );
        console.log("Registered identity & set metadata for:", admin);

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {DeployLib} from "./DeployLib.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";

/// Deploys core + common modules in one go. Safe to run on Anvil.
contract DeployUmbrella is Script {
    using DeployLib for *;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        // Core (re-usable)
        DeployLib.Core memory core = DeployLib.deployCore();
        console.log("VerificationLogger:", address(core.logger));
        console.log("TrustScore:", address(core.trust));
        console.log("UserIdentityRegistry:", address(core.registry));

        // Verification stack
        DeployLib.VerificationStack memory vf = DeployLib
            .deployVerificationStack(
                address(core.logger),
                address(core.registry),
                address(core.trust)
            );
        console.log("FaceVerificationManager:", address(vf.face));
        console.log("AadhaarVerificationManager:", address(vf.aadhaar));
        console.log("IncomeVerificationManager:", address(vf.income));

        // Offline + Mobile
        DeployLib.deployOfflineMobile(vm.addr(pk));

        // Organizations
        DeployLib.deployOrganizations(
            address(core.logger),
            address(core.registry),
            address(core.trust)
        );

        // Guardian + Anchor
        (, , ZkKeyRegistry zkReg) = DeployLib.deployGuardianAnchor(
            address(core.logger),
            address(core.registry),
            address(core.trust)
        );
        console.log("ZkKeyRegistry:", address(zkReg));

        // Governance
        DeployLib.deployGovernance(address(core.logger), address(core.trust));

        vm.stopBroadcast();

        // Verify indexing using DevOpsTools
        address lastLogger = DevOpsTools.get_most_recent_deployment(
            "VerificationLogger",
            block.chainid
        );
        console.log("Most recent VerificationLogger:", lastLogger);
    }
}

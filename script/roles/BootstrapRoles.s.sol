// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";

/// Grants SCORE_MANAGER_ROLE on TrustScore to the UserIdentityRegistry.
/// Usage:
///  forge script script/roles/BootstrapRoles.s.sol:BootstrapRoles \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
/// Env vars:
///  - TRUST_SCORE_ADDRESS: deployed TrustScore
///  - REGISTRY_ADDRESS: deployed UserIdentityRegistry (grantee)
contract BootstrapRoles is Script {
    function run() external {
        bool skipLookup = vm.envOr("SKIP_DEVOPS_LOOKUP", false);
        address trustAddr = vm.envOr("TRUST_SCORE_ADDRESS", address(0));
        address registryAddr = vm.envOr("REGISTRY_ADDRESS", address(0));
        if (trustAddr == address(0) && !skipLookup) {
            trustAddr = DevOpsTools.get_most_recent_deployment(
                "TrustScore",
                block.chainid
            );
        }
        if (registryAddr == address(0) && !skipLookup) {
            registryAddr = DevOpsTools.get_most_recent_deployment(
                "UserIdentityRegistry",
                block.chainid
            );
        }
        require(
            trustAddr != address(0) && registryAddr != address(0),
            "missing deployments"
        );

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (pk != 0) {
            vm.startBroadcast(pk);
        } else {
            vm.startBroadcast();
        }
        bytes32 role = keccak256("SCORE_MANAGER_ROLE");
        TrustScore(trustAddr).grantRole(role, registryAddr);
        vm.stopBroadcast();
        console.log("Granted SCORE_MANAGER_ROLE to registry", registryAddr);
    }
}

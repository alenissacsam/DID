// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
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
        address trustAddr = vm.envAddress("TRUST_SCORE_ADDRESS");
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        require(
            trustAddr != address(0) && registryAddr != address(0),
            "missing envs"
        );

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        bytes32 role = keccak256("SCORE_MANAGER_ROLE");
        TrustScore(trustAddr).grantRole(role, registryAddr);
        vm.stopBroadcast();
        console.log("Granted SCORE_MANAGER_ROLE to registry", registryAddr);
    }
}

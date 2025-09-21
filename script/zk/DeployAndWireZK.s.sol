// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {ZKProofManager} from "../../src/verification/ZKProofManager.sol";

/// Usage:
///  forge script script/zk/DeployAndWireZK.s.sol:DeployAndWireZK \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
///
/// Env vars:
///  - DEPLOY_ZKPM = true|false (default true)
///  - ZKPM_ADDRESS = existing ZKProofManager (if DEPLOY_ZKPM=false)
///  - AGE_VERIFIER_ADDR, ATTR_VERIFIER_ADDR, INCOME_VERIFIER_ADDR, AGE_MAX_VERIFIER_ADDR
///  - ZK_ROOT (optional) hex bytes32 to anchor
contract DeployAndWireZK is Script {
    function run() external {
        bool deploy = vm.envOr("DEPLOY_ZKPM", true);
        address zkpmAddr = vm.envOr("ZKPM_ADDRESS", address(0));
        address ageVerifier = vm.envAddress("AGE_VERIFIER_ADDR");
        address attrVerifier = vm.envAddress("ATTR_VERIFIER_ADDR");
        address incomeVerifier = vm.envAddress("INCOME_VERIFIER_ADDR");
        address ageMaxVerifier = vm.envAddress("AGE_MAX_VERIFIER_ADDR");

        bytes32 rootToAnchor = vm.envOr("ZK_ROOT", bytes32(0));

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
        zkpm.addProofType("age_gte", ageVerifier);
        console.log("Added proof type 0 (age_gte):", ageVerifier);
        zkpm.addProofType("attr_eq", attrVerifier);
        console.log("Added proof type 1 (attr_eq):", attrVerifier);
        zkpm.addProofType("income_gte", incomeVerifier);
        console.log("Added proof type 2 (income_gte):", incomeVerifier);
        zkpm.addProofType("age_lte", ageMaxVerifier);
        console.log("Added proof type 3 (age_lte):", ageMaxVerifier);

        if (rootToAnchor != bytes32(0)) {
            zkpm.anchorRoot(rootToAnchor);
            console.log("Anchored root");
        }

        vm.stopBroadcast();
    }
}

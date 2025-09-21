// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {DeployLib} from "../deploy/DeployLib.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";

contract DeployGuardianAndAnchor is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        (, , ZkKeyRegistry zkReg) = DeployLib.deployGuardianAnchor(
            logger,
            registry,
            trust
        );
        zkReg; // silence warning
        vm.stopBroadcast();
    }
}

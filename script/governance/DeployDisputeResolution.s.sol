// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {DeployLib} from "../deploy/DeployLib.sol";

contract DeployDisputeResolution is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        DeployLib.deployGovernance(logger, trust);
        vm.stopBroadcast();
    }
}

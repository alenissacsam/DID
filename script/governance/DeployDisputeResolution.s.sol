// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DisputeResolution} from "../../src/governance/DisputeResolution.sol";

contract DeployDisputeResolution is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        // For EconomicIncentives param, pass address(0) if not used in your flow
        address econ = vm.envOr("ECON_INCENTIVES_ADDRESS", address(0));
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        DisputeResolution disp = new DisputeResolution(logger, econ, trust);
        console.log("DisputeResolution:", address(disp));
        vm.stopBroadcast();
    }
}

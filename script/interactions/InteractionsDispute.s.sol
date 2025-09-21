// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {DisputeResolution} from "../../src/governance/DisputeResolution.sol";

contract InteractionsDispute is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address user = vm.addr(pk);
        vm.startBroadcast(pk);

        address dispAddr = DevOpsTools.get_most_recent_deployment(
            "DisputeResolution",
            block.chainid
        );
        DisputeResolution disp = DisputeResolution(dispAddr);

        // Grant arbitrator role to broadcaster so we can vote later
        disp.grantRole(keccak256("ARBITRATOR_ROLE"), user);
        console.log("Arbitrator role granted to:", user);

        // Create a demo dispute against self (use different address if desired)
        disp.createDispute(
            address(0x1111111111111111111111111111111111111111),
            DisputeResolution.DisputeType.TechnicalIssue,
            "Demo Title",
            "Demo description",
            "ipfs://evidence",
            keccak256("evidence")
        );
        console.log("Demo dispute created");

        vm.stopBroadcast();
    }
}

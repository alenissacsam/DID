// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {ZKProofManager} from "../../src/verification/ZKProofManager.sol";

contract InteractionsZkManager is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        address zkMgrAddr = DevOpsTools.get_most_recent_deployment(
            "ZKProofManager",
            block.chainid
        );
        ZKProofManager zk = ZKProofManager(zkMgrAddr);

        // Add common proof types (if not already added). This may revert if duplicates; ignore.
        try zk.addProofType("age-min", address(0xA001)) {} catch {}
        try zk.addProofType("attr-eq", address(0xA002)) {} catch {}
        try zk.addProofType("income-min", address(0xA003)) {} catch {}
        try zk.addProofType("age-max", address(0xA004)) {} catch {}

        // Anchor a dummy root for local testing
        try zk.anchorRoot(bytes32(uint256(0xabc))) {
            console.log("Root anchored");
        } catch {
            console.log("Root already anchored or missing role");
        }

        vm.stopBroadcast();
    }
}

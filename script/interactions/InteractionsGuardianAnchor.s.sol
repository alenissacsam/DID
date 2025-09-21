// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {GuardianManager} from "../../src/advanced_features/GuardianManager.sol";
import {GlobalCredentialAnchor} from "../../src/privacy_cross-chain/GlobalCredentialAnchor.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";

contract InteractionsGuardianAnchor is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address user = vm.addr(pk);
        vm.startBroadcast(pk);

        address guardianAddr = DevOpsTools.get_most_recent_deployment(
            "GuardianManager",
            block.chainid
        );
        address anchorAddr = DevOpsTools.get_most_recent_deployment(
            "GlobalCredentialAnchor",
            block.chainid
        );

        GuardianManager guardian = GuardianManager(guardianAddr);
        GlobalCredentialAnchor anchor = GlobalCredentialAnchor(anchorAddr);

        // Setup guardian set with one guardian (self as placeholder) and threshold 1
        address[] memory gs = new address[](1);
        gs[0] = user;
        string[] memory rel = new string[](1);
        rel[0] = "self";
        try guardian.setupGuardianSet(gs, rel, 1) {
            console.log("Guardian set created");
        } catch {
            console.log("Guardian set already exists or failed");
        }

        // Anchor a credential batch of one
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256("cred");
        address[] memory holders = new address[](1);
        holders[0] = user;
        string[] memory types = new string[](1);
        types[0] = "DEMO";
        anchor.submitCredentialBatch(
            hashes,
            holders,
            types,
            "ipfs://batch-meta"
        );
        console.log("Anchored 1 credential");

        // Register a dummy zk key using ZkKeyRegistry
        address zkRegAddr = DevOpsTools.get_most_recent_deployment(
            "ZkKeyRegistry",
            block.chainid
        );
        ZkKeyRegistry zkReg = ZkKeyRegistry(zkRegAddr);
        try zkReg.setKey("groth16", hex"deadbeef") {
            console.log("ZK key registered via ZkKeyRegistry");
        } catch {
            console.log("ZK key registration failed or already set");
        }

        vm.stopBroadcast();
    }
}

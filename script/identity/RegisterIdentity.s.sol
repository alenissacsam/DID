// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";

/// Usage:
///  forge script script/identity/RegisterIdentity.s.sol:RegisterIdentity \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
///
/// Env vars:
///  - REGISTRY_ADDRESS: deployed UserIdentityRegistry
///  - USER_ADDRESS: user to register (defaults to broadcaster)
///  - IDENTITY_COMMITMENT: bytes32 hex (optional). If not provided, a dev commitment
///    will be derived as keccak256(abi.encodePacked("LOCAL_DEV", user)).
contract RegisterIdentity is Script {
    function run() external {
        // Optional env override, otherwise resolve latest deployment via DevOpsTools
        bool skipLookup = vm.envOr("SKIP_DEVOPS_LOOKUP", false);
        address registryAddr = vm.envOr("REGISTRY_ADDRESS", address(0));
        if (registryAddr == address(0) && !skipLookup) {
            registryAddr = DevOpsTools.get_most_recent_deployment(
                "UserIdentityRegistry",
                block.chainid
            );
        }
        require(registryAddr != address(0), "UserIdentityRegistry not found");
        address user = vm.envOr("USER_ADDRESS", address(0));
        bytes32 providedCommitment = vm.envOr(
            "IDENTITY_COMMITMENT",
            bytes32(0)
        );

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        address sender = pk != 0
            ? vm.addr(pk)
            : address(
                uint160(uint256(keccak256(abi.encodePacked("SIM_SENDER"))))
            );
        if (user == address(0)) {
            user = sender; // default to broadcaster
        }

        bytes32 commitment = providedCommitment != bytes32(0)
            ? providedCommitment
            : keccak256(abi.encodePacked("LOCAL_DEV", user));

        console.log("UserIdentityRegistry:", registryAddr);
        console.log("User:", user);
        console.logBytes32(commitment);

        if (pk != 0) {
            vm.startBroadcast(pk);
        } else {
            vm.startBroadcast();
        }
        UserIdentityRegistry(registryAddr).registerIdentity(user, commitment);
        vm.stopBroadcast();

        console.log("registerIdentity done");
    }
}

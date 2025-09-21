// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
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
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        address user = vm.envOr("USER_ADDRESS", address(0));
        bytes32 providedCommitment = vm.envOr(
            "IDENTITY_COMMITMENT",
            bytes32(0)
        );

        require(registryAddr != address(0), "REGISTRY_ADDRESS not set");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        address sender = vm.addr(pk);
        if (user == address(0)) {
            user = sender; // default to broadcaster
        }

        bytes32 commitment = providedCommitment != bytes32(0)
            ? providedCommitment
            : keccak256(abi.encodePacked("LOCAL_DEV", user));

        console.log("UserIdentityRegistry:", registryAddr);
        console.log("User:", user);
        console.logBytes32(commitment);

        vm.startBroadcast(pk);
        UserIdentityRegistry(registryAddr).registerIdentity(user, commitment);
        vm.stopBroadcast();

        console.log("registerIdentity done");
    }
}

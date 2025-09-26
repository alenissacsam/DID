// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";

/// Interaction: Set a user's metadata URI in the UserIdentityRegistry.
/// Usage:
///  forge script script/interactions/SetIdentityMetadata.s.sol:SetIdentityMetadata \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
///
/// Env:
///  - USER_ADDRESS (optional; defaults to broadcaster)
///  - IDENTITY_METADATA_URI (required)
///  - REGISTRY_ADDRESS (optional; auto-resolves via DevOpsTools if absent)
contract SetIdentityMetadata is Script {
    function run() external {
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
        string memory uri = vm.envString("IDENTITY_METADATA_URI");
        require(bytes(uri).length > 0, "IDENTITY_METADATA_URI not set");

        // Robust private key parsing: support both decimal (envUint) and hex (envBytes32)
        uint256 pk = 0;
        try vm.envUint("PRIVATE_KEY") returns (uint256 v) {
            pk = v;
        } catch {}
        if (pk == 0) {
            try vm.envBytes32("PRIVATE_KEY") returns (bytes32 v2) {
                pk = uint256(v2);
            } catch {}
        }
        address sender = pk != 0
            ? vm.addr(pk)
            : address(
                uint160(uint256(keccak256(abi.encodePacked("SIM_SENDER"))))
            );
        if (user == address(0) && pk != 0) {
            // Default to the broadcaster only if we have a concrete key
            user = sender;
        }

        console.log("UserIdentityRegistry:", registryAddr);
        console.log("User:", user);
        console.log("URI:", uri);
        console.log("Sender:", sender);

        if (pk != 0) {
            vm.startBroadcast(pk);
        } else {
            vm.startBroadcast();
        }
        UserIdentityRegistry(registryAddr).setMetadataURI(user, uri);
        vm.stopBroadcast();

        console.log("setMetadataURI done");
    }
}

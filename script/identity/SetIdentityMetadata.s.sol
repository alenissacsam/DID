// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";

/// Usage:
///  forge script script/identity/SetIdentityMetadata.s.sol:SetIdentityMetadata \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY \
///    --broadcast -vvvv
///
/// Required env vars:
///  - REGISTRY_ADDRESS: deployed UserIdentityRegistry address
///  - USER_ADDRESS: the user whose metadata to set (defaults to broadcaster)
///  - IDENTITY_METADATA_URI: e.g. ipfs://<CID>
contract SetIdentityMetadata is Script {
    function run() external {
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        address user = vm.envOr("USER_ADDRESS", address(0));
        string memory uri = vm.envString("IDENTITY_METADATA_URI");

        require(registryAddr != address(0), "REGISTRY_ADDRESS not set");
        require(bytes(uri).length > 0, "IDENTITY_METADATA_URI not set");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        address sender = vm.addr(pk);
        if (user == address(0)) {
            user = sender; // default to broadcaster
        }

        console.log("UserIdentityRegistry:", registryAddr);
        console.log("User:", user);
        console.log("URI:", uri);
        console.log("Sender:", sender);

        vm.startBroadcast(pk);
        UserIdentityRegistry registry = UserIdentityRegistry(registryAddr);
        registry.setMetadataURI(user, uri);
        vm.stopBroadcast();

        console.log("setMetadataURI done");
    }
}

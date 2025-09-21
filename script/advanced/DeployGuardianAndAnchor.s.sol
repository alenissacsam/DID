// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {GuardianManager} from "../../src/advanced_features/GuardianManager.sol";
import {GlobalCredentialAnchor} from "../../src/privacy_cross-chain/GlobalCredentialAnchor.sol";

contract DeployGuardianAndAnchor is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        GuardianManager guardian = new GuardianManager(logger, registry, trust);
        console.log("GuardianManager:", address(guardian));

        GlobalCredentialAnchor anchor = new GlobalCredentialAnchor(logger);
        console.log("GlobalCredentialAnchor:", address(anchor));

        vm.stopBroadcast();
    }
}

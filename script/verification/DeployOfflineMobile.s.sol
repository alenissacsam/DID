// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {DeployLib} from "../deploy/DeployLib.sol";

contract DeployOfflineMobile is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);

        vm.startBroadcast(pk);
        DeployLib.deployOfflineMobile(admin);
        // We don't use the addresses here, but DeployUmbrella will print summaries.
        vm.stopBroadcast();
    }
}

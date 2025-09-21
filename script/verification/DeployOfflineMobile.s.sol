// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {OfflineVerificationManager} from "../../src/verification/OfflineVerificationManager.sol";
import {MobileVerificationInterface} from "../../src/verification/MobileVerificationInterface.sol";

contract DeployOfflineMobile is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);

        vm.startBroadcast(pk);
        OfflineVerificationManager offline = new OfflineVerificationManager(admin);
        console.log("OfflineVerificationManager:", address(offline));

        MobileVerificationInterface mobile = new MobileVerificationInterface(address(offline));
        console.log("MobileVerificationInterface:", address(mobile));
        vm.stopBroadcast();
    }
}

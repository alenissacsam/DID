// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DeployLib} from "../deploy/DeployLib.sol";

contract DeployFaceAadhaarIncome is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        DeployLib.VerificationStack memory stack = DeployLib
            .deployVerificationStack(logger, registry, trust);
        console.log("FaceVerificationManager:", address(stack.face));
        console.log("AadhaarVerificationManager:", address(stack.aadhaar));
        console.log("IncomeVerificationManager:", address(stack.income));

        vm.stopBroadcast();
    }
}

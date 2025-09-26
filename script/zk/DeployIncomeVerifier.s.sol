// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {Groth16Verifier} from "../../tools/zk-circuits/build/IncomeVerifier.sol";

contract DeployIncomeVerifier is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        Groth16Verifier verifier = new Groth16Verifier();
        console.log("INCOME_GTE Groth16Verifier:", address(verifier));

        vm.stopBroadcast();
    }
}

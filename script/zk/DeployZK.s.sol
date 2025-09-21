// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";

interface IZKProofManager {
    function addProofType(
        string calldata name,
        address verifierContract
    ) external;
}

contract DeployZK is Script {
    function run() external {
        vm.startBroadcast();

        address zkpm = vm.envAddress("ZKPM_ADDRESS");

        address ageGte = vm.envAddress("AGE_GTE_VERIFIER");
        address ageLte = vm.envAddress("AGE_LTE_VERIFIER");
        address attrEq = vm.envAddress("ATTR_EQ_VERIFIER");
        address incomeGte = vm.envAddress("INCOME_GTE_VERIFIER");

        IZKProofManager pm = IZKProofManager(zkpm);
        pm.addProofType("age_gte", ageGte);
        console.log("Registered age_gte ->", ageGte);
        pm.addProofType("age_lte", ageLte);
        console.log("Registered age_lte ->", ageLte);
        pm.addProofType("attr_equals", attrEq);
        console.log("Registered attr_equals ->", attrEq);
        pm.addProofType("income_gte", incomeGte);
        console.log("Registered income_gte ->", incomeGte);

        vm.stopBroadcast();
    }
}

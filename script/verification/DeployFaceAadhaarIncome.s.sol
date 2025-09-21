// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {FaceVerificationManager} from "../../src/verification/FaceVerificationManager.sol";
import {AadhaarVerificationManager} from "../../src/verification/AadhaarVerificationManager.sol";
import {IncomeVerificationManager} from "../../src/verification/IncomeVerificationManager.sol";

interface IUserIdentityRegistryLike {
    function isRegistered(address user) external view returns (bool);
}
interface ITrustScoreLike {
    function getTrustScore(address user) external view returns (uint256);
}

contract DeployFaceAadhaarIncome is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        FaceVerificationManager face = new FaceVerificationManager(logger, registry, trust);
        console.log("FaceVerificationManager:", address(face));

        AadhaarVerificationManager aadhaar = new AadhaarVerificationManager(
            logger, registry, trust, address(face)
        );
        console.log("AadhaarVerificationManager:", address(aadhaar));

        IncomeVerificationManager income = new IncomeVerificationManager(
            logger, registry, trust, address(aadhaar)
        );
        console.log("IncomeVerificationManager:", address(income));

        vm.stopBroadcast();
    }
}

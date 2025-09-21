// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {FaceVerificationManager} from "../../src/verification/FaceVerificationManager.sol";
import {AadhaarVerificationManager} from "../../src/verification/AadhaarVerificationManager.sol";
import {IncomeVerificationManager} from "../../src/verification/IncomeVerificationManager.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";

contract InteractionsVerification is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address user = vm.addr(pk);
        vm.startBroadcast(pk);

        address logger = DevOpsTools.get_most_recent_deployment(
            "VerificationLogger",
            block.chainid
        );
        address trust = DevOpsTools.get_most_recent_deployment(
            "TrustScore",
            block.chainid
        );
        address registry = DevOpsTools.get_most_recent_deployment(
            "UserIdentityRegistry",
            block.chainid
        );
        address faceAddr = DevOpsTools.get_most_recent_deployment(
            "FaceVerificationManager",
            block.chainid
        );
        address aadhaarAddr = DevOpsTools.get_most_recent_deployment(
            "AadhaarVerificationManager",
            block.chainid
        );
        address incomeAddr = DevOpsTools.get_most_recent_deployment(
            "IncomeVerificationManager",
            block.chainid
        );

        // Ensure roles are wired for logging
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        VerificationLogger(logger).grantRole(LOGGER_ROLE, trust);
        VerificationLogger(logger).grantRole(LOGGER_ROLE, registry);

        // Register the broadcaster if needed
        try UserIdentityRegistry(registry).isRegistered(user) returns (
            bool ok
        ) {
            if (!ok) {
                bytes32 commitment = keccak256(
                    abi.encodePacked("LOCAL_DEV", user)
                );
                UserIdentityRegistry(registry).registerIdentity(
                    user,
                    commitment
                );
            }
        } catch {
            // Assume needs manager role; if this reverts, run CoreInteractions first
        }

        // Face flow
        FaceVerificationManager face = FaceVerificationManager(faceAddr);
        face.requestFaceVerification(keccak256("faceHash"), keccak256("live"));
        face.completeFaceVerification(user, true, "MockProvider", hex"01");
        console.log("Face verified");

        // Aadhaar flow
        AadhaarVerificationManager aadhaar = AadhaarVerificationManager(
            aadhaarAddr
        );
        aadhaar.requestAadhaarVerification(
            keccak256("aadhaarHash"),
            keccak256("otp"),
            "OTP"
        );
        aadhaar.completeAadhaarVerification(user, true, hex"01");
        console.log("Aadhaar verified");

        // Income flow
        IncomeVerificationManager income = IncomeVerificationManager(
            incomeAddr
        );
        income.requestIncomeVerification(
            keccak256("income"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
        income.completeIncomeVerification(user, true, hex"01");
        console.log("Income verified");

        vm.stopBroadcast();
    }
}

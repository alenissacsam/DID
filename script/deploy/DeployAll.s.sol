// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {Script, console} from "forge-std/Script.sol";

contract DeployAll is Script {
    function run() external {
        vm.startBroadcast();

        VerificationLogger verificationLogger = new VerificationLogger();
        console.log("VerificationLogger deployed at:", address(verificationLogger));

        TrustScore trustScore = new TrustScore(address(verificationLogger));
        console.log("TrustScore deployed at:", address(trustScore));

        UserIdentityRegistry userIdentityRegistry =
            new UserIdentityRegistry(address(verificationLogger), address(trustScore));
        console.log("UserIdentityRegistry deployed at:", address(userIdentityRegistry));

        vm.stopBroadcast();
    }
}

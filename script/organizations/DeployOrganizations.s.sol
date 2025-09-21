// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {RecognitionManager} from "../../src/organizations/RecognitionManager.sol";

contract DeployOrganizations is Script {
    function run() external {
        address logger = vm.envAddress("LOGGER_ADDRESS");
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address trust = vm.envAddress("TRUST_SCORE_ADDRESS");

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        CertificateManager cert = new CertificateManager(logger, registry, trust);
        console.log("CertificateManager:", address(cert));

        RecognitionManager recog = new RecognitionManager(trust, logger, address(cert));
        console.log("RecognitionManager:", address(recog));

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {RecognitionManager} from "../../src/organizations/RecognitionManager.sol";

contract InteractionsOrganizations is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address issuer = vm.addr(pk);
        vm.startBroadcast(pk);

        address certAddr = DevOpsTools.get_most_recent_deployment(
            "CertificateManager",
            block.chainid
        );
        address recogAddr = DevOpsTools.get_most_recent_deployment(
            "RecognitionManager",
            block.chainid
        );

        CertificateManager cert = CertificateManager(certAddr);
        RecognitionManager recog = RecognitionManager(recogAddr);

        // Grant roles to broadcaster for demo
        cert.grantRole(keccak256("ISSUER_ROLE"), issuer);
        recog.grantRole(keccak256("BADGE_ADMIN_ROLE"), issuer);
        recog.grantRole(keccak256("MINTER_ROLE"), issuer);

        // Issue a certificate to self (demo)
        uint256 certId = cert.issueCertificate(
            issuer,
            "DEMO_CERT",
            "ipfs://demo-cert",
            365 days,
            keccak256("zk"),
            keccak256("idcomm"),
            25
        );
        console.log("Issued certificate:", certId);

        // Award a default badge id 1 if exists
        recog.awardBadge(1, issuer, "Auto badge awarded", keccak256("proof"));
        console.log("Badge 1 awarded to:", issuer);

        vm.stopBroadcast();
    }
}

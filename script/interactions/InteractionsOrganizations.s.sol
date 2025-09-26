// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";

contract InteractionsOrganizations is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address issuer = vm.addr(pk);
        vm.startBroadcast(pk);

        address certAddr = DevOpsTools.get_most_recent_deployment(
            "CertificateManager",
            block.chainid
        );

        CertificateManager cert = CertificateManager(certAddr);

        // Grant roles to broadcaster for demo
        cert.grantRole(keccak256("ISSUER_ROLE"), issuer);
        // Recognition system removed; badge roles obsolete.

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

        // Recognition system removed; no badge awarding.

        vm.stopBroadcast();
    }
}

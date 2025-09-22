// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";

contract CertificateManagerTest is Test {
    VerificationLogger logger;
    UserIdentityRegistry registry;
    TrustScore trust;
    CertificateManager cert;

    address alice = address(0xA11CE);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));

        cert = new CertificateManager(
            address(logger),
            address(registry),
            address(trust)
        );

        // Grant logger & score manager roles to CertificateManager so it can log and update trust
        logger.grantRole(logger.LOGGER_ROLE(), address(cert));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(cert));

        // Allow TrustScore to log and this test/registry to initialize users
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(this));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(this));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));

        // Prepare Alice in TrustScore
        // Register identity (initializes trust via registry)
        registry.registerIdentity(alice, keccak256("alice_ic"));

        // Boost Alice's trust to meet MIN_TRUST_SCORE_FOR_CERTIFICATE (75)
        trust.updateScore(alice, 100, "bootstrap");
    }

    function test_issue_and_revoke_certificate() public {
        // Grant issuer role to test contract (constructor already gave ADMIN_ROLE to this contract)
        cert.grantRole(cert.ISSUER_ROLE(), address(this));

        // Issue
        uint256 certId = cert.issueCertificate({
            holder: alice,
            certificateType: "DEMO",
            metadataUri: "ipfs://demo",
            validityPeriod: 365 days,
            zkProofHash: keccak256("zk"),
            identityCommitment: keccak256("id"),
            requiredTrustScore: 0
        });

        assertGt(certId, 0, "certId should be > 0");
        assertEq(cert.ownerOf(certId), alice, "owner should be Alice");
        assertTrue(
            cert.verifyCertificate(certId),
            "certificate should be valid"
        );

        // Revoke
        cert.revokeCertificate(certId, "violation");
        assertFalse(
            cert.verifyCertificate(certId),
            "certificate should be invalid after revoke"
        );
    }
}

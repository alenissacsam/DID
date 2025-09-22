// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {CertificateManager} from "src/organizations/CertificateManager.sol";
import {OrganizationStorage} from "src/organizations/OrganizationStorage.sol";
import {TestOrganization} from "test/utils/TestOrganization.sol";

contract OrganizationEndToEndTest is Test {
    VerificationLogger logger;
    UserIdentityRegistry registry;
    TrustScore trust;
    CertificateManager certs;
    TestOrganization org;

    address admin = address(0xA1);
    address orgAddr = address(0xB2);
    address holder = address(0xC3);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        certs = new CertificateManager(
            address(logger),
            address(registry),
            address(trust)
        );

        // Allow components to log
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        logger.grantRole(logger.LOGGER_ROLE(), address(certs));
        // Org contract (will be deployed next) also needs to log

        // Org contract
        org = new TestOrganization(
            address(certs),
            address(trust),
            address(logger)
        );

        // Grant logger role to org contract and allow it to update trust scores
        logger.grantRole(logger.LOGGER_ROLE(), address(org));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(org));

        // Grant roles for registry and certs
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), admin);
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));
        certs.grantRole(certs.DEFAULT_ADMIN_ROLE(), address(org));
        certs.grantRole(certs.ADMIN_ROLE(), address(org));
        // CertificateManager updates TrustScore on issuance/revocation
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(certs));
    }

    function test_end_to_end_organization_register_approve_issue() public {
        // Register identity and initialize score (test contract has REGISTRY_MANAGER_ROLE by default)
        registry.registerIdentity(holder, bytes32("commit"));
        // Give the holder enough initial trust for certificate issuance
        vm.prank(address(registry));
        trust.updateScore(holder, 80, "Participation");

        // Register and approve organization
        org.registerOrganization(
            orgAddr,
            "OrgName",
            OrganizationStorage.OrganizationType.University,
            "IN",
            "KA",
            "BLR",
            "REG123",
            "https://org",
            "org@x.com",
            "ipfs://meta",
            keccak256("kyc")
        );

        // Approve org (test has VERIFIER_ROLE)
        // Initialize org in TrustScore so approve can bump its score
        vm.prank(address(org));
        trust.initializeUser(orgAddr);
        org.approveOrganization(orgAddr);

        // Grant issuer role to org so it can issue certificates
        org.grantIssuerRole(orgAddr);

        // Make org the caller for issuing
        certs.grantRole(certs.ISSUER_ROLE(), orgAddr);

        // Issue a certificate to holder
        vm.prank(orgAddr);
        uint256 certId = certs.issueCertificate(
            holder,
            "Degree",
            "ipfs://degree",
            365 days,
            keccak256("proof"),
            bytes32("commit"),
            75
        );

        assertTrue(certs.verifyCertificate(certId));
        assertEq(certs.ownerOf(certId), holder);
    }
}

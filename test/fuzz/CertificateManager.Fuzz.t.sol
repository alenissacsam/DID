// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {CertificateManager} from "src/organizations/CertificateManager.sol";

contract CertificateManagerFuzzTest is Test {
    VerificationLogger logger;
    TrustScore trust;
    UserIdentityRegistry reg;
    CertificateManager certs;
    address admin = address(0xDD);
    address issuer = address(0xEE);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        reg = new UserIdentityRegistry(address(logger), address(trust));
        certs = new CertificateManager(
            address(logger),
            address(reg),
            address(trust)
        );
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(certs));
        logger.grantRole(logger.LOGGER_ROLE(), address(reg));
        reg.grantRole(reg.REGISTRY_MANAGER_ROLE(), admin);
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(reg));
        // CertificateManager updates trust scores on issuance/revocation
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(certs));
        certs.grantRole(certs.ISSUER_ROLE(), issuer);
    }

    function testFuzz_issue_certificate(
        address holder,
        uint64 validityDays,
        uint8 reqScore
    ) public {
        vm.assume(holder != address(0));
        validityDays = validityDays % 365;
        uint256 validityPeriod = uint256(validityDays) * 1 days;
        uint256 requiredTrust = 50 + (uint256(reqScore) % 100);

        vm.prank(admin);
        reg.registerIdentity(holder, keccak256(abi.encodePacked(holder, "c1")));
        // Boost score high enough
        vm.prank(address(reg));
        trust.updateScore(holder, 200, "Participation");

        // Query commitment (no special sender required)
        bytes32 ic = reg.getIdentityCommitment(holder);
        // Call as issuer for the actual issuance
        vm.prank(issuer);
        uint256 id = certs.issueCertificate(
            holder,
            "Course",
            "ipfs://cid",
            validityPeriod,
            keccak256("proof"),
            ic,
            requiredTrust
        );

        assertTrue(certs.verifyCertificate(id));
        assertEq(certs.ownerOf(id), holder);
    }
}

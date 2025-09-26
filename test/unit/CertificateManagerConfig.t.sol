// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {CertificateManager} from "src/organizations/CertificateManager.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract CertificateManagerConfigTest is Test {
    CertificateManager cert;
    VerificationLogger logger;
    UserIdentityRegistry registry;
    TrustScore trust;

    address holder = address(0xABCD);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        cert = new CertificateManager(
            address(logger),
            address(registry),
            address(trust)
        );

        // roles & permissions
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        logger.grantRole(logger.LOGGER_ROLE(), address(cert));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(cert));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(this));
        cert.grantRole(cert.ISSUER_ROLE(), address(this));
        cert.grantRole(cert.ADMIN_ROLE(), address(this));

        // Register identity (initializes trust score) then boost
        registry.registerIdentity(holder, bytes32("ic1"));
        trust.updateScore(holder, 80, "bootstrap");
    }

    function test_change_rewards_affects_issue_and_revoke() public {
        // Change rewards
        cert.setTrustScoreRewards(20, -5);

        int256 beforeScore = int256(trust.getTrustScore(holder));
        uint256 id = cert.issueCertificate(
            holder,
            "TYPE",
            "uri",
            30 days,
            bytes32("zk"),
            bytes32("unused"),
            70
        );
        int256 afterIssue = int256(trust.getTrustScore(holder));
        assertEq(afterIssue - beforeScore, 20, "issue reward applied");

        // Revoke
        cert.revokeCertificate(id, "bad");
        int256 afterRevoke = int256(trust.getTrustScore(holder));
        assertEq(afterRevoke - afterIssue, -5, "revoke penalty applied");
    }
}

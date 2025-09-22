// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {RecognitionManager} from "../../src/organizations/RecognitionManager.sol";

contract RecognitionManagerTest is Test {
    VerificationLogger logger;
    TrustScore trust;
    UserIdentityRegistry registry;
    CertificateManager cert;
    RecognitionManager recog;

    address bob = address(0xB0B);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        cert = new CertificateManager(
            address(logger),
            address(registry),
            address(trust)
        );
        recog = new RecognitionManager(
            address(trust),
            address(logger),
            address(cert)
        );

        // Roles
        logger.grantRole(logger.LOGGER_ROLE(), address(recog));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(recog));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(this));
        recog.grantRole(recog.BADGE_ADMIN_ROLE(), address(this));
        recog.grantRole(recog.MINTER_ROLE(), address(this));

        // Init bob trust
        trust.initializeUser(bob);
        trust.updateScore(bob, 30, "bootstrap");
    }

    function test_create_award_revoke_badge() public {
        uint256 badgeId = recog.createBadge(
            RecognitionManager.BadgeType.Achievement,
            RecognitionManager.BadgeRarity.Common,
            "Helper",
            "Helped the community",
            "ipfs://image",
            "",
            10,
            0,
            true,
            keccak256("criteria"),
            0
        );
        assertGt(badgeId, 0, "badgeId");

        // Award
        recog.awardBadge(badgeId, bob, "kudos", keccak256("ev"));
        assertEq(recog.balanceOf(bob, badgeId), 1);

        // Revoke
        recog.revokeBadge(badgeId, bob, "spam");
        assertEq(recog.balanceOf(bob, badgeId), 0);
    }
}

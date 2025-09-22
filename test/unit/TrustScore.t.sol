// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";

contract TrustScoreTest is Test {
    TrustScore score;
    VerificationLogger logger;
    address manager = address(this);
    address user = address(0xAAAA);

    function setUp() public {
        logger = new VerificationLogger();
        score = new TrustScore(address(logger));
        // allow score contract to log
        logger.grantRole(logger.LOGGER_ROLE(), address(score));
        // grant role already done in constructor to msg.sender (this contract)
    }

    function test_initialize_and_get() public {
        score.initializeUser(user);
        uint256 total = score.getTrustScore(user);
        assertEq(total, 0);
    }

    function test_update_increases_components_and_total() public {
        score.initializeUser(user);
        // Use positive delta to trigger setting FACE_VERIFICATION_SCORE
        score.updateScore(user, 1, "Face verification completed");
        uint256 total1 = score.getTrustScore(user);
        assertGt(total1, 0);

        score.updateScore(user, 10, "Educational certificate issued");
        uint256 total2 = score.getTrustScore(user);
        assertGe(total2, total1);
    }

    function test_lock_unlock() public {
        score.initializeUser(user);
        score.lockScore(user, "test");
        assertTrue(score.isScoreLocked(user));
        score.unlockScore(user);
        assertFalse(score.isScoreLocked(user));
    }
}

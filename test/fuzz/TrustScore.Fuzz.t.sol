// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract TrustScoreFuzzTest is Test {
    VerificationLogger logger;
    TrustScore trust;
    address manager = address(this);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), manager);
    }

    function testFuzz_updateScore_bounds(
        address user,
        int256 delta,
        string memory reason
    ) public {
        vm.assume(user != address(0));
        vm.assume(bytes(reason).length > 0);
        // Clamp delta range to avoid very large values
        int256 d = delta;
        if (d > 100) d = 100;
        if (d < -100) d = -100;

        trust.initializeUser(user);
        // Use normalized reason strings from contract so categorization doesn't revert on MAX constraints
        string memory r = bytes(reason).length % 2 == 0
            ? "Participation"
            : "Educational certificate issued";
        trust.updateScore(user, d, r);
        uint256 score = trust.getTrustScore(user);
        assertLe(score, trust.MAX_SCORE());
    }

    function testFuzz_lock_unlock(address user) public {
        vm.assume(user != address(0));
        trust.initializeUser(user);
        trust.lockScore(user, "test");
        assertTrue(trust.isScoreLocked(user));
        trust.unlockScore(user);
        assertFalse(trust.isScoreLocked(user));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";

contract DummyLoggerTS is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

contract TrustScore_Extended is Test {
    TrustScore ts;
    DummyLoggerTS logger;
    address user = address(0xABCD);
    bytes32 constant SCORE_MANAGER_ROLE = keccak256("SCORE_MANAGER_ROLE");

    function setUp() public {
        logger = new DummyLoggerTS();
        ts = new TrustScore(address(logger)); // test contract has admin + manager roles
    }

    function test_initializeUser_and_reverts() public {
        vm.expectRevert(bytes("Invalid user address"));
        ts.initializeUser(address(0));
        ts.initializeUser(user);
        vm.expectRevert(bytes("User already initialized"));
        ts.initializeUser(user);
    }

    function test_positive_reason_variants() public {
        ts.initializeUser(user);
        ts.updateScore(user, 1, "Face verification completed"); // face
        ts.updateScore(user, 1, "Aadhaar verification completed"); // aadhaar
        ts.updateScore(user, 10, "Income verification completed"); // income increment
        ts.updateScore(user, 5, "Educational certificate issued"); // certificate
        ts.updateScore(user, 3, "Badge awarded"); // reputation path 1
        ts.updateScore(user, 2, "Auto badge awarded"); // reputation path 2
        ts.updateScore(user, 4, "Participation event"); // participation fallback path
        // getDetailedScore returns (total, face, aadhaar, income, certificate, participation, reputation, penalty, lastUpdated, isLocked)
        (
            uint256 total,
            uint256 face,
            uint256 aadhaar,
            uint256 income,
            uint256 cert,
            uint256 participation,
            uint256 reputation,
            ,
            ,

        ) = ts.getDetailedScore(user);
        assertEq(face, ts.FACE_VERIFICATION_SCORE());
        assertEq(aadhaar, ts.AADHAAR_VERIFICATION_SCORE());
        // income >=10, cert >=5, participation >=4, reputation >= (3+2)
        assertGe(income, 10);
        assertGe(cert, 5);
        assertGe(participation, 4);
        assertGe(reputation, 5);
        assertGt(total, 0);
    }

    function test_negative_reason_variants_and_penalty() public {
        ts.initializeUser(user);
        // add some positives first
        ts.updateScore(user, 1, "Face verification completed");
        ts.updateScore(user, 1, "Aadhaar verification completed");
        ts.updateScore(user, 10, "Income verification completed");
        // revoke face
        ts.updateScore(user, -1, "Face verification revoked");
        // revoke aadhaar
        ts.updateScore(user, -1, "Aadhaar verification revoked");
        // revoke income
        ts.updateScore(user, -1, "Income verification revoked");
        // generic penalty
        ts.updateScore(user, -5, "Policy violation");
        // Ensure some penalty applied (penalty >0) and specific component resets happened
        (
            uint256 total,
            uint256 face,
            uint256 aadhaar,
            uint256 income,
            ,
            ,
            ,
            uint256 penalty,
            ,

        ) = ts.getDetailedScore(user);
        // MAX_SCORE is 1000 constant; instance exposes via public constant accessor ts.MAX_SCORE()
        assertEq(face, 0);
        assertEq(aadhaar, 0);
        assertEq(income, 0);
        assertGt(penalty, 0);
        assertLe(total, ts.MAX_SCORE());
    }

    function test_large_delta_reverts() public {
        ts.initializeUser(user);
        uint256 over = ts.MAX_SCORE() + 1; // precompute to avoid consuming expectRevert
        // Try positive overflow
        vm.expectRevert(bytes("Delta too large"));
        ts.updateScore(user, int256(over), "Participation event");
        // Try negative overflow
        vm.expectRevert(bytes("Delta too large"));
        ts.updateScore(user, -int256(over), "Policy violation");
    }

    function test_updateScore_reverts_missing_reason_not_initialized_locked()
        public
    {
        vm.expectRevert(bytes("Reason required"));
        ts.updateScore(user, 1, "");
        vm.expectRevert(bytes("User not initialized"));
        ts.updateScore(user, 1, "Participation event");
        ts.initializeUser(user);
        ts.lockScore(user, "abuse");
        vm.expectRevert(bytes("Score is locked"));
        ts.updateScore(user, 1, "Participation event");
    }

    function test_lock_and_unlock_reverts_and_state() public {
        ts.initializeUser(user);
        ts.lockScore(user, "investigation");
        assertTrue(ts.isScoreLocked(user));
        vm.expectRevert(bytes("Score already locked"));
        ts.lockScore(user, "again");
        ts.unlockScore(user);
        assertFalse(ts.isScoreLocked(user));
        vm.expectRevert(bytes("Score not locked"));
        ts.unlockScore(user);
    }

    function test_decay_applied_in_view_and_applyDecay_on_update() public {
        ts.initializeUser(user);
        ts.updateScore(user, 10, "Participation event");
        uint256 beforeScore = ts.getTrustScore(user);
        // warp 90 days -> 3 months decay (DECAY_RATE 1 per month)
        vm.warp(block.timestamp + 90 days);
        uint256 decayedView = ts.getTrustScore(user);
        assertEq(decayedView, beforeScore - 3);
        // Now call updateScore to trigger _applyDecay (penalty increment) then add +1
        ts.updateScore(user, 1, "Participation event");
        (uint256 total, , , , , , , , , ) = ts.getDetailedScore(user);
        // After applying decay, penalty increases by 3 then +1 participation added => approximate
        assertLe(total, beforeScore - 2); // loose assertion ensures decay applied
    }

    function test_getUsersAboveScore_and_history() public {
        ts.initializeUser(user);
        ts.updateScore(user, 10, "Participation event");
        address[] memory above = ts.getUsersAboveScore(5);
        assertEq(above.length, 1);
        // history entries should reflect updates (1 entry for update)
        TrustScore.ScoreHistory[] memory hist = ts.getScoreHistory(user);
        assertEq(hist.length, 1);
        assertEq(hist[0].delta, 10);
    }

    function test_score_caps_and_multiple_decay() public {
        ts.initializeUser(user);
        // Push certificate score near cap
        for (uint256 i = 0; i < 30; i++) {
            // 30 * 40 = 1200 but capped at 1000
            ts.updateScore(user, 40, "Educational certificate issued");
        }
        (uint256 total, , , , uint256 cert, , , , , ) = ts.getDetailedScore(
            user
        );
        assertLe(cert, ts.MAX_SCORE());
        // Warp 400 days (~13 months) => 13 decay points
        uint256 before = ts.getTrustScore(user);
        vm.warp(block.timestamp + 400 days);
        uint256 afterDecayView = ts.getTrustScore(user);
        assertEq(before - afterDecayView, 13); // 13 months * DECAY_RATE(1)
        // Apply decay again via update (+1 participation) ensures penalty increases
        ts.updateScore(user, 1, "Participation event");
        (
            uint256 total2,
            ,
            ,
            ,
            uint256 cert2,
            uint256 participation,
            ,
            uint256 penalty,
            ,

        ) = ts.getDetailedScore(user);
        assertLe(cert2, ts.MAX_SCORE());
        assertGt(penalty, 0);
        assertGt(participation, 0);
        assertLe(total2, total); // due to decay penalty accumulation
    }
}

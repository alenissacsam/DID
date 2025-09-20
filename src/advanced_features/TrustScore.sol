// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IVerificationLogger.sol";

contract TrustScore is AccessControl {
    bytes32 public constant SCORE_MANAGER_ROLE =
        keccak256("SCORE_MANAGER_ROLE");

    struct ScoreComponents {
        uint256 baseScore;
        uint256 faceVerificationScore;
        uint256 aadhaarVerificationScore;
        uint256 incomeVerificationScore;
        uint256 certificateScore;
        uint256 participationScore;
        uint256 reputationScore;
        uint256 penaltyScore;
        uint256 lastUpdated;
        uint256 totalInteractions;
        bool isLocked;
        uint256 lockPenalty;
    }

    struct ScoreHistory {
        int256 delta;
        string reason;
        uint256 timestamp;
        address updater;
    }

    mapping(address => ScoreComponents) public userScores;
    mapping(address => ScoreHistory[]) public scoreHistory;
    mapping(address => bool) public hasScore;

    address[] public scoredUsers;
    IVerificationLogger public verificationLogger;

    uint256 public constant MAX_SCORE = 1000;
    uint256 public constant INITIAL_SCORE = 0;
    uint256 public constant DECAY_RATE = 1; // Points lost per month of inactivity
    uint256 public constant FACE_VERIFICATION_SCORE = 25;
    uint256 public constant AADHAAR_VERIFICATION_SCORE = 50;
    uint256 public constant INCOME_VERIFICATION_BASE_SCORE = 25;
    uint256 public constant LOCK_PENALTY = 20;

    event ScoreUpdated(
        address indexed user,
        int256 delta,
        uint256 newScore,
        string reason
    );
    event UserInitialized(address indexed user);
    event ScoreDecayed(address indexed user, uint256 decayAmount);
    event ScoreLocked(address indexed user, uint256 penalty);
    event ScoreUnlocked(address indexed user);

    constructor(address _verificationLogger) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SCORE_MANAGER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
    }

    function initializeUser(
        address user
    ) external onlyRole(SCORE_MANAGER_ROLE) {
        require(user != address(0), "Invalid user address");
        require(!hasScore[user], "User already initialized");

        userScores[user] = ScoreComponents({
            baseScore: INITIAL_SCORE,
            faceVerificationScore: 0,
            aadhaarVerificationScore: 0,
            incomeVerificationScore: 0,
            certificateScore: 0,
            participationScore: 0,
            reputationScore: 0,
            penaltyScore: 0,
            lastUpdated: block.timestamp,
            totalInteractions: 0,
            isLocked: false,
            lockPenalty: 0
        });

        hasScore[user] = true;
        scoredUsers.push(user);

        verificationLogger.logEvent(
            "USER_TRUST_SCORE_INITIALIZED",
            user,
            bytes32(INITIAL_SCORE)
        );
        emit UserInitialized(user);
    }

    function updateScore(
        address user,
        int256 delta,
        string memory reason
    ) external onlyRole(SCORE_MANAGER_ROLE) {
        require(user != address(0), "Invalid user address");
        require(bytes(reason).length > 0, "Reason required");
        require(hasScore[user], "User not initialized");
        require(!userScores[user].isLocked, "Score is locked");

        ScoreComponents storage components = userScores[user];

        // Apply decay before update
        _applyDecay(user);

        // Categorize the score update based on reason
        bytes32 reasonHash = keccak256(bytes(reason));

        if (delta > 0) {
            uint256 increase = uint256(delta);
            require(increase <= MAX_SCORE, "Delta too large");

            if (reasonHash == keccak256("Face verification completed")) {
                components.faceVerificationScore = FACE_VERIFICATION_SCORE;
            } else if (
                reasonHash == keccak256("Aadhaar verification completed")
            ) {
                components
                    .aadhaarVerificationScore = AADHAAR_VERIFICATION_SCORE;
            } else if (
                reasonHash == keccak256("Income verification completed")
            ) {
                uint256 newScore = components.incomeVerificationScore +
                    increase;
                components.incomeVerificationScore = newScore > MAX_SCORE
                    ? MAX_SCORE
                    : newScore;
            } else if (
                reasonHash == keccak256("Educational certificate issued")
            ) {
                uint256 newScore = components.certificateScore + increase;
                components.certificateScore = newScore > MAX_SCORE
                    ? MAX_SCORE
                    : newScore;
            } else if (
                reasonHash == keccak256("Badge awarded") ||
                reasonHash == keccak256("Auto badge awarded")
            ) {
                uint256 newScore = components.reputationScore + increase;
                components.reputationScore = newScore > MAX_SCORE
                    ? MAX_SCORE
                    : newScore;
            } else {
                uint256 newScore = components.participationScore + increase;
                components.participationScore = newScore > MAX_SCORE
                    ? MAX_SCORE
                    : newScore;
            }
        } else {
            uint256 decrease = uint256(-delta);
            require(decrease <= MAX_SCORE, "Delta too large");

            if (reasonHash == keccak256("Face verification revoked")) {
                components.faceVerificationScore = 0;
            } else if (
                reasonHash == keccak256("Aadhaar verification revoked")
            ) {
                components.aadhaarVerificationScore = 0;
            } else if (reasonHash == keccak256("Income verification revoked")) {
                components.incomeVerificationScore = 0;
            } else {
                uint256 newPenalty = components.penaltyScore + decrease;
                components.penaltyScore = newPenalty > MAX_SCORE
                    ? MAX_SCORE
                    : newPenalty;
            }
        }

        // Update metadata
        components.lastUpdated = block.timestamp;
        components.totalInteractions = components.totalInteractions + 1;

        // Add to history
        scoreHistory[user].push(
            ScoreHistory({
                delta: delta,
                reason: reason,
                timestamp: block.timestamp,
                updater: msg.sender
            })
        );

        uint256 newTotalScore = _calculateTotalScore(user);

        verificationLogger.logEvent(
            "TRUST_SCORE_UPDATED",
            user,
            keccak256(abi.encodePacked(delta, reason, newTotalScore))
        );

        emit ScoreUpdated(user, delta, newTotalScore, reason);
    }

    function lockScore(
        address user,
        string memory reason
    ) external onlyRole(SCORE_MANAGER_ROLE) {
        require(hasScore[user], "User not initialized");
        require(!userScores[user].isLocked, "Score already locked");

        userScores[user].isLocked = true;
        userScores[user].lockPenalty = LOCK_PENALTY;

        verificationLogger.logEvent(
            "TRUST_SCORE_LOCKED",
            user,
            keccak256(bytes(reason))
        );
        emit ScoreLocked(user, LOCK_PENALTY);
    }

    function unlockScore(address user) external onlyRole(SCORE_MANAGER_ROLE) {
        require(hasScore[user], "User not initialized");
        require(userScores[user].isLocked, "Score not locked");

        userScores[user].isLocked = false;
        userScores[user].lockPenalty = 0;

        verificationLogger.logEvent("TRUST_SCORE_UNLOCKED", user, bytes32(0));
        emit ScoreUnlocked(user);
    }

    function getTrustScore(address user) external view returns (uint256) {
        if (!hasScore[user]) return 0;
        return _calculateTotalScoreWithDecay(user);
    }

    function getDetailedScore(
        address user
    )
        external
        view
        returns (
            uint256 totalScore,
            uint256 faceVerificationScore,
            uint256 aadhaarVerificationScore,
            uint256 incomeVerificationScore,
            uint256 certificateScore,
            uint256 participationScore,
            uint256 reputationScore,
            uint256 penaltyScore,
            uint256 lastUpdated,
            bool isLocked
        )
    {
        if (!hasScore[user]) return (0, 0, 0, 0, 0, 0, 0, 0, 0, false);

        ScoreComponents memory components = userScores[user];
        uint256 total = _calculateTotalScoreWithDecay(user);

        return (
            total,
            components.faceVerificationScore,
            components.aadhaarVerificationScore,
            components.incomeVerificationScore,
            components.certificateScore,
            components.participationScore,
            components.reputationScore,
            components.penaltyScore,
            components.lastUpdated,
            components.isLocked
        );
    }

    function getVerificationLevel(
        address user
    ) external view returns (uint256) {
        if (!hasScore[user]) return 0;

        ScoreComponents memory components = userScores[user];
        uint256 level = 0;

        if (components.faceVerificationScore > 0) level = 1;
        if (
            components.faceVerificationScore > 0 &&
            components.aadhaarVerificationScore > 0
        ) level = 2;
        if (
            components.faceVerificationScore > 0 &&
            components.aadhaarVerificationScore > 0 &&
            components.incomeVerificationScore > 0
        ) level = 3;

        return level;
    }

    function getUsersAboveScore(
        uint256 minScore
    ) external view returns (address[] memory) {
        address[] memory result = new address[](scoredUsers.length);
        uint256 count = 0;

        for (uint256 i = 0; i < scoredUsers.length; i++) {
            if (_calculateTotalScoreWithDecay(scoredUsers[i]) >= minScore) {
                result[count] = scoredUsers[i];
                count++;
            }
        }

        assembly {
            mstore(result, count)
        }

        return result;
    }

    function getScoreHistory(
        address user
    ) external view returns (ScoreHistory[] memory) {
        return scoreHistory[user];
    }

    function isScoreLocked(address user) external view returns (bool) {
        if (!hasScore[user]) return false;
        return userScores[user].isLocked;
    }

    function _calculateTotalScore(address user) private view returns (uint256) {
        ScoreComponents memory components = userScores[user];

        uint256 totalPositive = components.baseScore +
            components.faceVerificationScore +
            components.aadhaarVerificationScore +
            components.incomeVerificationScore +
            components.certificateScore +
            components.participationScore +
            components.reputationScore;

        uint256 totalPenalty = components.penaltyScore + components.lockPenalty;

        if (totalPenalty >= totalPositive) return 0;

        uint256 finalScore = totalPositive - totalPenalty;
        return finalScore > MAX_SCORE ? MAX_SCORE : finalScore;
    }

    function _calculateTotalScoreWithDecay(
        address user
    ) private view returns (uint256) {
        if (!hasScore[user]) return 0;

        uint256 baseScore = _calculateTotalScore(user);
        uint256 decayAmount = _calculateDecay(user);

        if (decayAmount >= baseScore) return 0;
        return baseScore - decayAmount;
    }

    function _calculateDecay(address user) private view returns (uint256) {
        ScoreComponents memory components = userScores[user];
        uint256 timeSinceUpdate = block.timestamp - components.lastUpdated;
        uint256 monthsSinceUpdate = timeSinceUpdate / 30 days;

        // Prevent overflow and ensure reasonable decay
        if (monthsSinceUpdate > 100) monthsSinceUpdate = 100; // Cap at 100 months

        return monthsSinceUpdate * DECAY_RATE;
    }

    function _applyDecay(address user) private {
        uint256 decayAmount = _calculateDecay(user);
        if (decayAmount > 0) {
            userScores[user].penaltyScore =
                userScores[user].penaltyScore +
                decayAmount;
            userScores[user].lastUpdated = block.timestamp;
            emit ScoreDecayed(user, decayAmount);
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/IUserIdentityRegistry.sol";
import "../interfaces/ITrustScore.sol";

interface IAadhaarVerificationManager {
    function isAadhaarVerified(address user) external view returns (bool);
}

contract IncomeVerificationManager is AccessControl, ReentrancyGuard {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant INCOME_ORACLE_ROLE =
        keccak256("INCOME_ORACLE_ROLE");

    enum IncomeRange {
        Below1Lakh, // < 1,00,000
        Lakh1to5, // 1,00,000 - 5,00,000
        Lakh5to10, // 5,00,000 - 10,00,000
        Lakh10to25, // 10,00,000 - 25,00,000
        Above25Lakh // > 25,00,000
    }

    struct IncomeVerification {
        address user;
        bytes32 incomeProofHash;
        IncomeRange incomeRange;
        uint256 timestamp;
        bool isVerified;
        bool isActive;
        string verificationSource; // "ITR", "BankStatement", "SalarySlip", "GST"
        uint256 expiryDate;
        bool isRenewed;
    }

    mapping(address => IncomeVerification) public incomeVerifications;
    mapping(address => IncomeVerification[]) public incomeHistory;

    IVerificationLogger public verificationLogger;
    IUserIdentityRegistry public userRegistry;
    ITrustScore public trustScore;
    IAadhaarVerificationManager public aadhaarVerificationManager;

    uint256 public constant INCOME_VERIFICATION_SCORE = 25;
    uint256 public constant INCOME_VERIFICATION_VALIDITY = 365 days; // 1 year

    event IncomeVerificationRequested(
        address indexed user,
        IncomeRange incomeRange
    );
    event IncomeVerificationCompleted(
        address indexed user,
        bool success,
        string source
    );
    event IncomeVerificationRevoked(address indexed user, string reason);
    event IncomeVerificationExpired(address indexed user);
    event IncomeVerificationRenewed(address indexed user, IncomeRange newRange);

    constructor(
        address _verificationLogger,
        address _userRegistry,
        address _trustScore,
        address _aadhaarVerificationManager
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(INCOME_ORACLE_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        userRegistry = IUserIdentityRegistry(_userRegistry);
        trustScore = ITrustScore(_trustScore);
        aadhaarVerificationManager = IAadhaarVerificationManager(
            _aadhaarVerificationManager
        );
    }

    function requestIncomeVerification(
        bytes32 incomeProofHash,
        IncomeRange incomeRange,
        string memory verificationSource
    ) external nonReentrant {
        require(userRegistry.isRegistered(msg.sender), "User not registered");
        require(
            !userRegistry.isIdentityLocked(msg.sender),
            "Identity is locked"
        );
        require(
            aadhaarVerificationManager.isAadhaarVerified(msg.sender),
            "Aadhaar verification required"
        );
        require(
            !incomeVerifications[msg.sender].isActive,
            "Income verification already active"
        );
        require(incomeProofHash != bytes32(0), "Invalid income proof hash");
        require(
            bytes(verificationSource).length > 0,
            "Empty verification source"
        );
        require(uint256(incomeRange) <= 4, "Invalid income range");

        bytes32 sourceHash = keccak256(bytes(verificationSource));
        /*
        require(
            sourceHash == keccak256("ITR") ||
                sourceHash == keccak256("BankStatement") ||
                sourceHash == keccak256("SalarySlip") ||
                sourceHash == keccak256("GST"),
            "Invalid verification source"
        );*/

        incomeVerifications[msg.sender] = IncomeVerification({
            user: msg.sender,
            incomeProofHash: incomeProofHash,
            incomeRange: incomeRange,
            timestamp: block.timestamp,
            isVerified: false,
            isActive: true,
            verificationSource: verificationSource,
            expiryDate: 0,
            isRenewed: false
        });

        verificationLogger.logEvent(
            "INCOME_VERIFICATION_REQUESTED",
            msg.sender,
            incomeProofHash
        );

        emit IncomeVerificationRequested(msg.sender, incomeRange);
    }

    function completeIncomeVerification(
        address user,
        bool success,
        bytes memory oracleSignature
    ) public onlyRole(INCOME_ORACLE_ROLE) {
        require(
            incomeVerifications[user].isActive,
            "No active income verification"
        );
        require(
            _verifyOracleSignature(user, success, oracleSignature),
            "Invalid oracle signature"
        );

        incomeVerifications[user].isVerified = success;

        if (success) {
            incomeVerifications[user].expiryDate =
                block.timestamp +
                INCOME_VERIFICATION_VALIDITY;

            userRegistry.updateVerificationStatus(user, "income", true);

            uint256 bonus = _calculateIncomeBonus(
                incomeVerifications[user].incomeRange
            );
            trustScore.updateScore(
                user,
                int256(INCOME_VERIFICATION_SCORE + bonus),
                "Income verification completed"
            );

            // Store in history
            incomeHistory[user].push(incomeVerifications[user]);
        } else {
            incomeVerifications[user].isActive = false;
            trustScore.updateScore(user, -5, "Income verification failed");
        }

        verificationLogger.logEvent(
            success
                ? "INCOME_VERIFICATION_SUCCESS"
                : "INCOME_VERIFICATION_FAILED",
            user,
            keccak256(
                abi.encodePacked(
                    incomeVerifications[user].verificationSource,
                    success
                )
            )
        );

        emit IncomeVerificationCompleted(
            user,
            success,
            incomeVerifications[user].verificationSource
        );
    }

    function renewIncomeVerification(
        bytes32 newIncomeProofHash,
        IncomeRange newIncomeRange,
        string memory verificationSource
    ) external nonReentrant {
        require(
            incomeVerifications[msg.sender].isVerified,
            "No verified income to renew"
        );
        require(
            !_isIncomeVerificationExpired(msg.sender),
            "Current verification already expired"
        );
        require(newIncomeProofHash != bytes32(0), "Invalid income proof hash");

        bytes32 sourceHash = keccak256(bytes(verificationSource));

        require(
            sourceHash == keccak256("ITR") ||
                sourceHash == keccak256("BankStatement") ||
                sourceHash == keccak256("SalarySlip") ||
                sourceHash == keccak256("GST"),
            "Invalid verification source"
        );

        // Store current verification in history before renewal
        incomeHistory[msg.sender].push(incomeVerifications[msg.sender]);

        incomeVerifications[msg.sender] = IncomeVerification({
            user: msg.sender,
            incomeProofHash: newIncomeProofHash,
            incomeRange: newIncomeRange,
            timestamp: block.timestamp,
            isVerified: false,
            isActive: true,
            verificationSource: verificationSource,
            expiryDate: 0,
            isRenewed: true
        });

        verificationLogger.logEvent(
            "INCOME_VERIFICATION_RENEWAL_REQUESTED",
            msg.sender,
            newIncomeProofHash
        );

        emit IncomeVerificationRenewed(msg.sender, newIncomeRange);
    }

    function revokeIncomeVerification(
        address user,
        string memory reason
    ) external onlyRole(VERIFIER_ROLE) {
        require(incomeVerifications[user].isVerified, "Income not verified");

        uint256 deductionAmount = INCOME_VERIFICATION_SCORE +
            _calculateIncomeBonus(incomeVerifications[user].incomeRange);

        incomeVerifications[user].isVerified = false;
        incomeVerifications[user].isActive = false;

        userRegistry.updateVerificationStatus(user, "income", false);
        trustScore.updateScore(
            user,
            -int256(deductionAmount),
            "Income verification revoked"
        );

        verificationLogger.logEvent(
            "INCOME_VERIFICATION_REVOKED",
            user,
            keccak256(bytes(reason))
        );

        emit IncomeVerificationRevoked(user, reason);
    }

    function checkAndExpireVerifications(address[] memory users) external {
        for (uint256 i = 0; i < users.length; i++) {
            if (
                _isIncomeVerificationExpired(users[i]) &&
                incomeVerifications[users[i]].isVerified
            ) {
                _expireIncomeVerification(users[i]);
            }
        }
    }

    function bulkCompleteIncomeVerification(
        address[] memory users,
        bool[] memory successes,
        bytes[] memory signatures
    ) external onlyRole(INCOME_ORACLE_ROLE) {
        require(
            users.length == successes.length &&
                successes.length == signatures.length,
            "Array lengths must match"
        );

        for (uint256 i = 0; i < users.length; i++) {
            if (incomeVerifications[users[i]].isActive) {
                completeIncomeVerification(
                    users[i],
                    successes[i],
                    signatures[i]
                );
            }
        }
    }

    function isIncomeVerified(address user) external view returns (bool) {
        return
            incomeVerifications[user].isVerified &&
            incomeVerifications[user].isActive &&
            !_isIncomeVerificationExpired(user);
    }

    function getIncomeVerificationInfo(
        address user
    )
        external
        view
        returns (
            IncomeRange incomeRange,
            uint256 timestamp,
            bool isVerified,
            string memory verificationSource,
            uint256 expiryDate,
            bool isExpired
        )
    {
        IncomeVerification memory verification = incomeVerifications[user];
        return (
            verification.incomeRange,
            verification.timestamp,
            verification.isVerified,
            verification.verificationSource,
            verification.expiryDate,
            _isIncomeVerificationExpired(user)
        );
    }

    function getIncomeHistory(
        address user
    ) external view returns (IncomeVerification[] memory) {
        return incomeHistory[user];
    }

    function getIncomeRangeStats()
        external
        view
        returns (uint256[5] memory rangeCounts, uint256 totalVerified)
    {
        // This would require additional state tracking in production
        // For now, return placeholder values
        return ([uint256(0), 0, 0, 0, 0], 0);
    }

    function _calculateIncomeBonus(
        IncomeRange range
    ) private pure returns (uint256) {
        if (range == IncomeRange.Below1Lakh) return 0;
        if (range == IncomeRange.Lakh1to5) return 5;
        if (range == IncomeRange.Lakh5to10) return 10;
        if (range == IncomeRange.Lakh10to25) return 15;
        if (range == IncomeRange.Above25Lakh) return 20;
        return 0;
    }

    function _isIncomeVerificationExpired(
        address user
    ) private view returns (bool) {
        IncomeVerification memory verification = incomeVerifications[user];
        return
            verification.expiryDate != 0 &&
            block.timestamp > verification.expiryDate;
    }

    function _expireIncomeVerification(address user) private {
        uint256 deductionAmount = INCOME_VERIFICATION_SCORE +
            _calculateIncomeBonus(incomeVerifications[user].incomeRange);

        incomeVerifications[user].isVerified = false;
        incomeVerifications[user].isActive = false;

        userRegistry.updateVerificationStatus(user, "income", false);
        trustScore.updateScore(
            user,
            -int256(deductionAmount),
            "Income verification expired"
        );

        verificationLogger.logEvent(
            "INCOME_VERIFICATION_EXPIRED",
            user,
            bytes32(0)
        );
        emit IncomeVerificationExpired(user);
    }

    function _verifyOracleSignature(
        address user,
        bool success,
        bytes memory signature
    ) private pure returns (bool) {
        // Simplified oracle signature verification - in production use proper verification
        return signature.length > 0 && user != address(0);
    }
}

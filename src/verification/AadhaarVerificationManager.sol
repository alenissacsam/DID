// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/IUserIdentityRegistry.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IFaceVerificationManager.sol";
import "../interfaces/IZkProofManager.sol";
import "./ZkTypes.sol";

contract AadhaarVerificationManager is AccessControl, ReentrancyGuard {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UIDAI_ORACLE_ROLE = keccak256("UIDAI_ORACLE_ROLE");

    struct AadhaarVerification {
        address user;
        bytes32 aadhaarHashCommitment;
        bytes32 otpHash;
        uint256 timestamp;
        bool isVerified;
        bool isActive;
        string verificationMethod; // "OTP", "Biometric", "eKYC"
        uint256 retryCount;
        uint256 lastRetry;
    }

    mapping(address => AadhaarVerification) public aadhaarVerifications;
    mapping(bytes32 => bool) public usedAadhaarHashes;
    mapping(address => uint256) public failedAttempts;

    IVerificationLogger public verificationLogger;
    IUserIdentityRegistry public userRegistry;
    ITrustScore public trustScore;
    IFaceVerificationManager public faceVerificationManager;
    IZkProofManager public zkProofManager;

    uint256 public constant AADHAAR_VERIFICATION_SCORE = 50;
    uint256 public constant MAX_RETRY_ATTEMPTS = 3;
    uint256 public constant RETRY_COOLDOWN = 2 hours;
    uint256 public constant MAX_FAILED_ATTEMPTS = 3;

    event AadhaarVerificationRequested(
        address indexed user,
        bytes32 aadhaarHashCommitment
    );
    event AadhaarVerificationCompleted(
        address indexed user,
        bool success,
        string method
    );
    event AadhaarVerificationRevoked(address indexed user, string reason);
    event RetryAttempt(address indexed user, uint256 attemptNumber);

    constructor(
        address _verificationLogger,
        address _userRegistry,
        address _trustScore,
        address _faceVerificationManager
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(UIDAI_ORACLE_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        userRegistry = IUserIdentityRegistry(_userRegistry);
        trustScore = ITrustScore(_trustScore);
        faceVerificationManager = IFaceVerificationManager(
            _faceVerificationManager
        );
    }

    function setZkProofManager(
        address _zkProofManager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        zkProofManager = IZkProofManager(_zkProofManager);
    }

    function requestAadhaarVerification(
        bytes32 aadhaarHashCommitment,
        bytes32 otpHash,
        string memory verificationMethod
    ) external nonReentrant {
        require(userRegistry.isRegistered(msg.sender), "User not registered");
        require(
            !userRegistry.isIdentityLocked(msg.sender),
            "Identity is locked"
        );
        require(
            faceVerificationManager.isFaceVerified(msg.sender),
            "Face verification required first"
        );
        require(
            !aadhaarVerifications[msg.sender].isActive,
            "Aadhaar verification already active"
        );
        require(
            !usedAadhaarHashes[aadhaarHashCommitment],
            "Aadhaar hash already used"
        );
        require(aadhaarHashCommitment != bytes32(0), "Invalid Aadhaar hash");
        require(otpHash != bytes32(0), "Invalid OTP hash");
        require(
            bytes(verificationMethod).length > 0,
            "Empty verification method"
        );
        require(
            failedAttempts[msg.sender] < MAX_FAILED_ATTEMPTS,
            "Too many failed attempts"
        );

        // bytes32 methodHash = keccak256(bytes(verificationMethod));

        /*require(
            methodHash == keccak256("OTP") ||
            methodHash == keccak256("Biometric") ||
            methodHash == keccak256("eKYC"),
            "Invalid verification method"
        );*/

        // Check retry cooldown
        AadhaarVerification storage existing = aadhaarVerifications[msg.sender];
        if (existing.retryCount > 0) {
            require(
                block.timestamp >= existing.lastRetry + RETRY_COOLDOWN,
                "Retry cooldown not expired"
            );
        }

        aadhaarVerifications[msg.sender] = AadhaarVerification({
            user: msg.sender,
            aadhaarHashCommitment: aadhaarHashCommitment,
            otpHash: otpHash,
            timestamp: block.timestamp,
            isVerified: false,
            isActive: true,
            verificationMethod: verificationMethod,
            retryCount: existing.retryCount + 1,
            lastRetry: block.timestamp
        });

        usedAadhaarHashes[aadhaarHashCommitment] = true;

        verificationLogger.logEvent(
            "AADHAAR_VERIFICATION_REQUESTED",
            msg.sender,
            aadhaarHashCommitment
        );

        emit AadhaarVerificationRequested(msg.sender, aadhaarHashCommitment);

        if (existing.retryCount > 0) {
            emit RetryAttempt(msg.sender, existing.retryCount + 1);
        }
    }

    function completeAadhaarVerification(
        address user,
        bool success,
        bytes memory uidaiSignature
    ) public onlyRole(UIDAI_ORACLE_ROLE) {
        require(
            aadhaarVerifications[user].isActive,
            "No active Aadhaar verification"
        );
        require(
            _verifyUidaiSignature(user, success, uidaiSignature),
            "Invalid UIDAI signature"
        );

        _finalizeAadhaarVerification(user, success);
        _afterVerificationLog(user, success);
    }

    // Optional path: complete Aadhaar using a ZK proof (e.g., attribute equality commitment)
    function completeAadhaarVerificationWithProof(
        address user,
        bytes memory uidaiSignature,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external onlyRole(UIDAI_ORACLE_ROLE) {
        require(
            aadhaarVerifications[user].isActive,
            "No active Aadhaar verification"
        );
        require(
            _verifyUidaiSignature(user, true, uidaiSignature),
            "Invalid UIDAI signature"
        );
        require(address(zkProofManager) != address(0), "ZK manager not set");

        zkProofManager.verifyProof(
            ZkTypes.attrEquals(),
            _pA,
            _pB,
            _pC,
            publicSignals,
            nullifier
        );

        _finalizeAadhaarVerification(user, true);
        _afterVerificationLog(user, true);
    }

    function _finalizeAadhaarVerification(address user, bool success) internal {
        aadhaarVerifications[user].isVerified = success;

        if (success) {
            userRegistry.updateVerificationStatus(
                user,
                IUserIdentityRegistry.VerificationKind.Aadhaar,
                true
            );
            trustScore.updateScore(
                user,
                int256(AADHAAR_VERIFICATION_SCORE),
                "Aadhaar verification completed"
            );

            // Reset failed attempts on success
            failedAttempts[user] = 0;
        } else {
            aadhaarVerifications[user].isActive = false;
            failedAttempts[user]++;

            // Apply penalty for failed verification
            trustScore.updateScore(user, -10, "Aadhaar verification failed");
        }
    }

    function _afterVerificationLog(address user, bool success) internal {
        verificationLogger.logEvent(
            success
                ? "AADHAAR_VERIFICATION_SUCCESS"
                : "AADHAAR_VERIFICATION_FAILED",
            user,
            keccak256(
                abi.encodePacked(
                    aadhaarVerifications[user].verificationMethod,
                    success
                )
            )
        );

        emit AadhaarVerificationCompleted(
            user,
            success,
            aadhaarVerifications[user].verificationMethod
        );
    }

    function revokeAadhaarVerification(
        address user,
        string memory reason
    ) external onlyRole(VERIFIER_ROLE) {
        require(aadhaarVerifications[user].isVerified, "Aadhaar not verified");

        aadhaarVerifications[user].isVerified = false;
        aadhaarVerifications[user].isActive = false;

        userRegistry.updateVerificationStatus(
            user,
            IUserIdentityRegistry.VerificationKind.Aadhaar,
            false
        );
        trustScore.updateScore(
            user,
            -int256(AADHAAR_VERIFICATION_SCORE),
            "Aadhaar verification revoked"
        );

        verificationLogger.logEvent(
            "AADHAAR_VERIFICATION_REVOKED",
            user,
            keccak256(bytes(reason))
        );

        emit AadhaarVerificationRevoked(user, reason);
    }

    function resetFailedAttempts(
        address user
    ) external onlyRole(VERIFIER_ROLE) {
        failedAttempts[user] = 0;

        verificationLogger.logEvent(
            "AADHAAR_VERIFICATION_ATTEMPTS_RESET",
            user,
            bytes32(0)
        );
    }

    function bulkCompleteAadhaarVerification(
        address[] memory users,
        bool[] memory successes,
        bytes[] memory signatures
    ) external onlyRole(UIDAI_ORACLE_ROLE) {
        require(
            users.length == successes.length &&
                successes.length == signatures.length,
            "Array lengths must match"
        );

        for (uint256 i = 0; i < users.length; i++) {
            if (aadhaarVerifications[users[i]].isActive) {
                completeAadhaarVerification(
                    users[i],
                    successes[i],
                    signatures[i]
                );
            }
        }
    }

    function isAadhaarVerified(address user) external view returns (bool) {
        return
            aadhaarVerifications[user].isVerified &&
            aadhaarVerifications[user].isActive;
    }

    function getAadhaarVerificationInfo(
        address user
    )
        external
        view
        returns (
            bytes32 aadhaarHashCommitment,
            uint256 timestamp,
            bool isVerified,
            string memory verificationMethod,
            uint256 retryCount,
            uint256 failedAttemptCount
        )
    {
        AadhaarVerification memory verification = aadhaarVerifications[user];
        return (
            verification.aadhaarHashCommitment,
            verification.timestamp,
            verification.isVerified,
            verification.verificationMethod,
            verification.retryCount,
            failedAttempts[user]
        );
    }

    function canRetryVerification(address user) external view returns (bool) {
        if (failedAttempts[user] >= MAX_FAILED_ATTEMPTS) return false;
        if (aadhaarVerifications[user].retryCount >= MAX_RETRY_ATTEMPTS) {
            return false;
        }

        AadhaarVerification memory verification = aadhaarVerifications[user];
        if (verification.retryCount > 0) {
            return block.timestamp >= verification.lastRetry + RETRY_COOLDOWN;
        }

        return true;
    }

    function getVerificationMethodStats(
        string memory /* method */
    )
        external
        pure
        returns (uint256 totalRequests, uint256 successfulVerifications)
    {
        // This would require additional state tracking in production
        // For now, return placeholder values
        return (0, 0);
    }

    function _verifyUidaiSignature(
        address user,
        bool success,
        bytes memory signature
    ) private pure returns (bool) {
        // Enhanced UIDAI signature verification
        require(signature.length >= 65, "Invalid signature length"); // Minimum signature length
        require(user != address(0), "Invalid user address");

        // In production, this would verify the signature against UIDAI's public key
        // For now, we ensure the signature has proper format
        bytes32 messageHash = keccak256(abi.encodePacked(user, success));

        // Simplified verification - in production use ecrecover or proper signature verification
        return signature.length > 0 && messageHash != bytes32(0);
    }
}

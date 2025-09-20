// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";

contract UserIdentityRegistry is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                           VARIABLES & STRUCTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_MANAGER_ROLE =
        keccak256("REGISTRY_MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    struct Identity {
        bytes32 identityCommitment;
        uint256 registeredAt;
        bool isActive;
        string metadataURI;
        bool faceVerified;
        bool aadhaarVerified;
        bool incomeVerified;
        uint256 verificationLevel; // 0=none, 1=face, 2=face+aadhaar, 3=all
        bool isLocked;
        uint256 lockExpiry;
    }

    mapping(address => Identity) public identities;
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => address) public commitmentToAddress;
    mapping(bytes32 => bool) public inactiveCommitments; // For privacy compliance

    IVerificationLogger public verificationLogger;
    ITrustScore public trustScore;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event IdentityRegistered(address indexed user, bytes32 indexed commitment);
    event IdentityDeregistered(address indexed user);
    event IdentityUpdated(address indexed user, bytes32 newCommitment);
    event VerificationStatusUpdated(
        address indexed user,
        string verificationType,
        bool status
    );
    event IdentityLocked(address indexed user, uint256 lockExpiry);
    event IdentityUnlocked(address indexed user);
    event CommitmentNullified(bytes32 indexed commitment);

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    constructor(address _verificationLogger, address _trustScore) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_MANAGER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        trustScore = ITrustScore(_trustScore);
    }

    function registerIdentity(
        address user,
        bytes32 identityCommitment
    ) external onlyRole(REGISTRY_MANAGER_ROLE) nonReentrant whenNotPaused {
        require(user != address(0), "Invalid user address");
        require(identityCommitment != bytes32(0), "Invalid commitment");
        require(!identities[user].isActive, "Identity already registered");
        require(!nullifiers[identityCommitment], "Commitment already used");
        require(
            !inactiveCommitments[identityCommitment],
            "Commitment was previously nullified"
        );

        identities[user] = Identity({
            identityCommitment: identityCommitment,
            registeredAt: block.timestamp,
            isActive: true,
            metadataURI: "",
            faceVerified: false,
            aadhaarVerified: false,
            incomeVerified: false,
            verificationLevel: 0,
            isLocked: false,
            lockExpiry: 0
        });

        nullifiers[identityCommitment] = true;
        commitmentToAddress[identityCommitment] = user;

        trustScore.initializeUser(user);

        verificationLogger.logEvent(
            "IDENTITY_REGISTERED",
            user,
            identityCommitment
        );
        emit IdentityRegistered(user, identityCommitment);
    }

    function updateVerificationStatus(
        address user,
        string memory verificationType,
        bool status
    ) external onlyRole(REGISTRY_MANAGER_ROLE) {
        require(identities[user].isActive, "Identity not registered");

        bytes32 verificationHash = keccak256(bytes(verificationType));

        if (verificationHash == keccak256("face")) {
            identities[user].faceVerified = status;
        } else if (verificationHash == keccak256("aadhaar")) {
            identities[user].aadhaarVerified = status;
        } else if (verificationHash == keccak256("income")) {
            identities[user].incomeVerified = status;
        } else {
            revert("Invalid verification type");
        }

        // Update verification level
        uint256 level = 0;
        if (identities[user].faceVerified) level = 1;
        if (identities[user].faceVerified && identities[user].aadhaarVerified) {
            level = 2;
        }
        if (
            identities[user].faceVerified &&
            identities[user].aadhaarVerified &&
            identities[user].incomeVerified
        ) {
            level = 3;
        }

        identities[user].verificationLevel = level;

        verificationLogger.logEvent(
            "VERIFICATION_STATUS_UPDATED",
            user,
            keccak256(abi.encodePacked(verificationType, status))
        );

        emit VerificationStatusUpdated(user, verificationType, status);
    }

    function lockIdentity(
        address user,
        uint256 lockDuration
    ) external onlyRole(REGISTRY_MANAGER_ROLE) {
        require(identities[user].isActive, "Identity not registered");

        identities[user].isLocked = true;
        identities[user].lockExpiry = block.timestamp + lockDuration;

        verificationLogger.logEvent(
            "IDENTITY_LOCKED",
            user,
            bytes32(block.timestamp + lockDuration)
        );
        emit IdentityLocked(user, identities[user].lockExpiry);
    }

    function unlockIdentity(
        address user
    ) external onlyRole(REGISTRY_MANAGER_ROLE) {
        require(identities[user].isActive, "Identity not registered");
        require(identities[user].isLocked, "Identity not locked");

        identities[user].isLocked = false;
        identities[user].lockExpiry = 0;

        verificationLogger.logEvent("IDENTITY_UNLOCKED", user, bytes32(0));
        emit IdentityUnlocked(user);
    }

    function updateIdentityCommitment(
        address user,
        bytes32 newCommitment
    ) external onlyRole(REGISTRY_MANAGER_ROLE) {
        require(identities[user].isActive, "Identity not registered");
        require(newCommitment != bytes32(0), "Invalid commitment");
        require(!nullifiers[newCommitment], "New commitment already used");
        require(
            !inactiveCommitments[newCommitment],
            "New commitment was previously nullified"
        );

        bytes32 oldCommitment = identities[user].identityCommitment;

        // Mark old commitment as inactive for privacy compliance
        inactiveCommitments[oldCommitment] = true;
        delete commitmentToAddress[oldCommitment];

        identities[user].identityCommitment = newCommitment;
        nullifiers[newCommitment] = true;
        commitmentToAddress[newCommitment] = user;

        verificationLogger.logEvent("IDENTITY_UPDATED", user, newCommitment);
        emit IdentityUpdated(user, newCommitment);
        emit CommitmentNullified(oldCommitment);
    }

    function deregisterIdentity(
        address user
    ) external onlyRole(REGISTRY_MANAGER_ROLE) {
        require(identities[user].isActive, "Identity not registered");

        bytes32 commitment = identities[user].identityCommitment;

        identities[user].isActive = false;
        inactiveCommitments[commitment] = true;
        delete commitmentToAddress[commitment];

        verificationLogger.logEvent("IDENTITY_DEREGISTERED", user, commitment);
        emit IdentityDeregistered(user);
        emit CommitmentNullified(commitment);
    }

    function isRegistered(address user) external view returns (bool) {
        return identities[user].isActive;
    }

    function isIdentityLocked(address user) external view returns (bool) {
        if (!identities[user].isLocked) return false;

        // Check if lock has expired
        if (block.timestamp > identities[user].lockExpiry) {
            return false;
        }

        return true;
    }

    function isIdentityLockedWithUpdate(address user) external returns (bool) {
        if (!identities[user].isLocked) return false;

        // Auto-unlock expired locks
        if (block.timestamp > identities[user].lockExpiry) {
            identities[user].isLocked = false;
            identities[user].lockExpiry = 0;

            if (address(verificationLogger) != address(0)) {
                verificationLogger.logEvent(
                    "IDENTITY_AUTO_UNLOCKED",
                    user,
                    bytes32(0)
                );
            }
            emit IdentityUnlocked(user);

            return false;
        }

        return true;
    }

    function getVerificationStatus(
        address user
    )
        external
        view
        returns (
            bool faceVerified,
            bool aadhaarVerified,
            bool incomeVerified,
            uint256 verificationLevel
        )
    {
        Identity memory identity = identities[user];
        return (
            identity.faceVerified,
            identity.aadhaarVerified,
            identity.incomeVerified,
            identity.verificationLevel
        );
    }

    function getIdentityCommitment(
        address user
    ) external view returns (bytes32) {
        require(identities[user].isActive, "Identity not registered");
        return identities[user].identityCommitment;
    }

    function getIdentityInfo(
        address user
    ) external view returns (Identity memory) {
        return identities[user];
    }

    function isCommitmentActive(
        bytes32 commitment
    ) external view returns (bool) {
        return
            nullifiers[commitment] &&
            !inactiveCommitments[commitment] &&
            commitmentToAddress[commitment] != address(0);
    }

    function isCommitmentValid(
        bytes32 commitment,
        address expectedUser
    ) external view returns (bool) {
        return
            nullifiers[commitment] &&
            !inactiveCommitments[commitment] &&
            commitmentToAddress[commitment] == expectedUser &&
            identities[expectedUser].isActive &&
            !identities[expectedUser].isLocked;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}

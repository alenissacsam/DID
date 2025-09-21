// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/IUserIdentityRegistry.sol";
import "../interfaces/ITrustScore.sol";

contract GuardianManager is AccessControl, ReentrancyGuard {
    bytes32 public constant GUARDIAN_ADMIN_ROLE = keccak256("GUARDIAN_ADMIN_ROLE");

    struct Guardian {
        address guardianAddress;
        string relationship;
        uint256 addedAt;
        bool isActive;
        uint256 trustScore;
    }

    struct GuardianSet {
        mapping(address => Guardian) guardians;
        address[] guardianList;
        uint256 threshold;
        uint256 maxGuardians;
        uint256 additionDelay;
        uint256 removalDelay;
        bool isSetup;
    }

    struct RecoveryProposal {
        address user;
        address newWallet;
        bytes32 recoveryData;
        mapping(address => bool) hasVoted;
        address[] votedGuardians;
        uint256 proposedAt;
        uint256 executionTime;
        bool isExecuted;
        bool isCancelled;
        string reason;
    }

    struct GuardianChange {
        address user;
        address guardian;
        bool isAddition; // true for addition, false for removal
        uint256 proposedAt;
        uint256 executionTime;
        bool isExecuted;
        string reason;
    }

    mapping(address => GuardianSet) private guardianSets;
    mapping(bytes32 => RecoveryProposal) public recoveryProposals;
    mapping(bytes32 => GuardianChange) public guardianChanges;

    uint256 private recoveryCounter;
    uint256 private changeCounter;

    IVerificationLogger public verificationLogger;
    IUserIdentityRegistry public userRegistry;
    ITrustScore public trustScore;

    uint256 public constant MIN_GUARDIAN_TRUST_SCORE = 50;
    uint256 public constant DEFAULT_GUARDIAN_DELAY = 7 days;
    uint256 public constant RECOVERY_EXECUTION_DELAY = 48 hours;
    uint256 public constant MAX_GUARDIANS = 5;

    event GuardianAdded(address indexed user, address indexed guardian, string relationship);
    event GuardianRemoved(address indexed user, address indexed guardian, string reason);
    event GuardianChangeProposed(
        bytes32 indexed changeId, address indexed user, address indexed guardian, bool isAddition
    );
    event GuardianChangeExecuted(bytes32 indexed changeId);
    event RecoveryProposed(bytes32 indexed recoveryId, address indexed user, address indexed newWallet);
    event RecoveryVoted(bytes32 indexed recoveryId, address indexed guardian);
    event RecoveryExecuted(bytes32 indexed recoveryId, address indexed user);
    event RecoveryCancelled(bytes32 indexed recoveryId, string reason);
    event ThresholdUpdated(address indexed user, uint256 newThreshold);

    constructor(address _verificationLogger, address _userRegistry, address _trustScore) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        userRegistry = IUserIdentityRegistry(_userRegistry);
        trustScore = ITrustScore(_trustScore);
    }

    function setupGuardianSet(address[] memory guardians, string[] memory relationships, uint256 threshold)
        external
        nonReentrant
    {
        require(userRegistry.isRegistered(msg.sender), "User not registered");
        require(!guardianSets[msg.sender].isSetup, "Guardian set already setup");
        require(guardians.length > 0 && guardians.length <= MAX_GUARDIANS, "Invalid guardian count");
        require(guardians.length == relationships.length, "Arrays length mismatch");
        require(threshold > 0 && threshold <= guardians.length, "Invalid threshold");

        GuardianSet storage guardianSet = guardianSets[msg.sender];

        for (uint256 i = 0; i < guardians.length; i++) {
            require(guardians[i] != address(0) && guardians[i] != msg.sender, "Invalid guardian address");
            require(!guardianSet.guardians[guardians[i]].isActive, "Duplicate guardian");
            require(trustScore.getTrustScore(guardians[i]) >= MIN_GUARDIAN_TRUST_SCORE, "Guardian trust score too low");

            guardianSet.guardians[guardians[i]] = Guardian({
                guardianAddress: guardians[i],
                relationship: relationships[i],
                addedAt: block.timestamp,
                isActive: true,
                trustScore: trustScore.getTrustScore(guardians[i])
            });

            guardianSet.guardianList.push(guardians[i]);
        }

        guardianSet.threshold = threshold;
        guardianSet.maxGuardians = MAX_GUARDIANS;
        guardianSet.additionDelay = DEFAULT_GUARDIAN_DELAY;
        guardianSet.removalDelay = DEFAULT_GUARDIAN_DELAY;
        guardianSet.isSetup = true;

        verificationLogger.logEvent(
            "GUARDIAN_SET_SETUP", msg.sender, keccak256(abi.encodePacked(guardians.length, threshold))
        );
    }

    function proposeGuardianChange(address guardian, string memory relationship, bool isAddition, string memory reason)
        external
        nonReentrant
        returns (bytes32)
    {
        require(guardianSets[msg.sender].isSetup, "Guardian set not setup");

        GuardianSet storage guardianSet = guardianSets[msg.sender];

        if (isAddition) {
            require(guardianSet.guardianList.length < guardianSet.maxGuardians, "Max guardians reached");
            require(guardian != address(0) && guardian != msg.sender, "Invalid guardian address");
            require(!guardianSet.guardians[guardian].isActive, "Guardian already exists");
            require(trustScore.getTrustScore(guardian) >= MIN_GUARDIAN_TRUST_SCORE, "Guardian trust score too low");
        } else {
            require(guardianSet.guardians[guardian].isActive, "Guardian not found");
            require(guardianSet.guardianList.length > 1, "Cannot remove last guardian");
        }

        changeCounter++;
        bytes32 changeId = keccak256(abi.encodePacked(msg.sender, guardian, changeCounter, block.timestamp));

        guardianChanges[changeId] = GuardianChange({
            user: msg.sender,
            guardian: guardian,
            isAddition: isAddition,
            proposedAt: block.timestamp,
            executionTime: block.timestamp + (isAddition ? guardianSet.additionDelay : guardianSet.removalDelay),
            isExecuted: false,
            reason: reason
        });

        verificationLogger.logEvent(
            isAddition ? "GUARDIAN_ADDITION_PROPOSED" : "GUARDIAN_REMOVAL_PROPOSED",
            msg.sender,
            keccak256(abi.encodePacked(guardian, reason))
        );

        emit GuardianChangeProposed(changeId, msg.sender, guardian, isAddition);
        return changeId;
    }

    function executeGuardianChange(bytes32 changeId) external nonReentrant {
        GuardianChange storage change = guardianChanges[changeId];
        require(change.user != address(0), "Invalid change ID");
        require(!change.isExecuted, "Change already executed");
        require(block.timestamp >= change.executionTime, "Delay not met");
        require(msg.sender == change.user, "Only user can execute");

        GuardianSet storage guardianSet = guardianSets[change.user];

        if (change.isAddition) {
            guardianSet.guardians[change.guardian] = Guardian({
                guardianAddress: change.guardian,
                relationship: "Added via proposal",
                addedAt: block.timestamp,
                isActive: true,
                trustScore: trustScore.getTrustScore(change.guardian)
            });

            guardianSet.guardianList.push(change.guardian);
            emit GuardianAdded(change.user, change.guardian, "Added via proposal");
        } else {
            guardianSet.guardians[change.guardian].isActive = false;
            _removeFromGuardianList(change.user, change.guardian);
            emit GuardianRemoved(change.user, change.guardian, change.reason);
        }

        change.isExecuted = true;

        verificationLogger.logEvent(
            "GUARDIAN_CHANGE_EXECUTED", change.user, keccak256(abi.encodePacked(changeId, change.guardian))
        );

        emit GuardianChangeExecuted(changeId);
    }

    function proposeRecovery(address user, address newWallet, bytes32 recoveryData, string memory reason)
        external
        nonReentrant
        returns (bytes32)
    {
        require(guardianSets[user].isSetup, "Guardian set not setup for user");
        require(guardianSets[user].guardians[msg.sender].isActive, "Not a valid guardian");
        require(newWallet != address(0) && newWallet != user, "Invalid new wallet");

        recoveryCounter++;
        bytes32 recoveryId = keccak256(abi.encodePacked(user, newWallet, recoveryCounter, block.timestamp));

        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        proposal.user = user;
        proposal.newWallet = newWallet;
        proposal.recoveryData = recoveryData;
        proposal.proposedAt = block.timestamp;
        proposal.executionTime = block.timestamp + RECOVERY_EXECUTION_DELAY;
        proposal.reason = reason;

        // Guardian automatically votes for their own proposal
        proposal.hasVoted[msg.sender] = true;
        proposal.votedGuardians.push(msg.sender);

        verificationLogger.logEvent(
            "RECOVERY_PROPOSED", user, keccak256(abi.encodePacked(recoveryId, newWallet, reason))
        );

        emit RecoveryProposed(recoveryId, user, newWallet);
        emit RecoveryVoted(recoveryId, msg.sender);

        return recoveryId;
    }

    function voteForRecovery(bytes32 recoveryId) external nonReentrant {
        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        require(proposal.user != address(0), "Invalid recovery ID");
        require(!proposal.isExecuted && !proposal.isCancelled, "Recovery not active");
        require(guardianSets[proposal.user].guardians[msg.sender].isActive, "Not a valid guardian");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        proposal.hasVoted[msg.sender] = true;
        proposal.votedGuardians.push(msg.sender);

        verificationLogger.logEvent(
            "RECOVERY_VOTED", proposal.user, keccak256(abi.encodePacked(recoveryId, msg.sender))
        );

        emit RecoveryVoted(recoveryId, msg.sender);
    }

    function executeRecovery(bytes32 recoveryId) external nonReentrant {
        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        require(proposal.user != address(0), "Invalid recovery ID");
        require(!proposal.isExecuted && !proposal.isCancelled, "Recovery not active");
        require(block.timestamp >= proposal.executionTime, "Execution delay not met");

        GuardianSet storage guardianSet = guardianSets[proposal.user];
        require(proposal.votedGuardians.length >= guardianSet.threshold, "Insufficient guardian votes");

        proposal.isExecuted = true;

        // Unlock user's identity and trust score
        userRegistry.unlockIdentity(proposal.user);
        trustScore.unlockScore(proposal.user);

        verificationLogger.logEvent(
            "RECOVERY_EXECUTED", proposal.user, keccak256(abi.encodePacked(recoveryId, proposal.newWallet))
        );

        emit RecoveryExecuted(recoveryId, proposal.user);
    }

    function cancelRecovery(bytes32 recoveryId, string memory reason) external {
        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        require(proposal.user != address(0), "Invalid recovery ID");
        require(!proposal.isExecuted && !proposal.isCancelled, "Recovery not active");
        require(msg.sender == proposal.user || hasRole(GUARDIAN_ADMIN_ROLE, msg.sender), "Not authorized to cancel");

        proposal.isCancelled = true;

        verificationLogger.logEvent(
            "RECOVERY_CANCELLED", proposal.user, keccak256(abi.encodePacked(recoveryId, reason))
        );

        emit RecoveryCancelled(recoveryId, reason);
    }

    function updateThreshold(uint256 newThreshold) external nonReentrant {
        require(guardianSets[msg.sender].isSetup, "Guardian set not setup");
        require(newThreshold > 0 && newThreshold <= guardianSets[msg.sender].guardianList.length, "Invalid threshold");

        guardianSets[msg.sender].threshold = newThreshold;

        verificationLogger.logEvent("GUARDIAN_THRESHOLD_UPDATED", msg.sender, bytes32(newThreshold));

        emit ThresholdUpdated(msg.sender, newThreshold);
    }

    function getGuardianSet(address user)
        external
        view
        returns (address[] memory guardians, uint256 threshold, bool isSetup)
    {
        GuardianSet storage guardianSet = guardianSets[user];
        return (guardianSet.guardianList, guardianSet.threshold, guardianSet.isSetup);
    }

    function getGuardianInfo(address user, address guardian)
        external
        view
        returns (string memory relationship, uint256 addedAt, bool isActive, uint256 currentTrustScore)
    {
        Guardian memory guardianInfo = guardianSets[user].guardians[guardian];
        return
            (guardianInfo.relationship, guardianInfo.addedAt, guardianInfo.isActive, trustScore.getTrustScore(guardian));
    }

    function getRecoveryInfo(bytes32 recoveryId)
        external
        view
        returns (
            address user,
            address newWallet,
            uint256 proposedAt,
            uint256 executionTime,
            uint256 currentVotes,
            uint256 requiredVotes,
            bool isExecuted,
            bool isCancelled
        )
    {
        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        return (
            proposal.user,
            proposal.newWallet,
            proposal.proposedAt,
            proposal.executionTime,
            proposal.votedGuardians.length,
            guardianSets[proposal.user].threshold,
            proposal.isExecuted,
            proposal.isCancelled
        );
    }

    function isGuardian(address user, address guardian) external view returns (bool) {
        return guardianSets[user].guardians[guardian].isActive;
    }

    function canExecuteRecovery(bytes32 recoveryId) external view returns (bool) {
        RecoveryProposal storage proposal = recoveryProposals[recoveryId];
        if (proposal.user == address(0) || proposal.isExecuted || proposal.isCancelled) return false;
        if (block.timestamp < proposal.executionTime) return false;
        return proposal.votedGuardians.length >= guardianSets[proposal.user].threshold;
    }

    function _removeFromGuardianList(address user, address guardian) private {
        address[] storage guardianList = guardianSets[user].guardianList;
        for (uint256 i = 0; i < guardianList.length; i++) {
            if (guardianList[i] == guardian) {
                guardianList[i] = guardianList[guardianList.length - 1];
                guardianList.pop();
                break;
            }
        }
    }
}

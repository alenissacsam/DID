// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";

interface IEconomicIncentives {
    function slash(address user, string memory reason) external;
}

contract DisputeResolution is AccessControl, ReentrancyGuard {
    bytes32 public constant ARBITRATOR_ROLE = keccak256("ARBITRATOR_ROLE");
    bytes32 public constant DISPUTE_ADMIN_ROLE = keccak256("DISPUTE_ADMIN_ROLE");

    enum DisputeStatus {
        Pending,
        UnderReview,
        VotingPhase,
        Resolved,
        Appealed,
        Executed,
        Rejected,
        Expired
    }
    enum DisputeType {
        CertificateValidity,
        OrganizationMisbehavior,
        FalseIdentity,
        TechnicalIssue,
        GovernanceDispute,
        TokenDispute,
        Other
    }

    struct Dispute {
        uint256 id;
        address challenger;
        address respondent;
        DisputeType disputeType;
        string title;
        string description;
        string evidenceUri;
        bytes32 evidenceHash;
        uint256 challengeBond;
        uint256 createdAt;
        uint256 reviewDeadline;
        uint256 votingDeadline;
        uint256 executionDeadline;
        DisputeStatus status;
        bool challengerWon;
        address[] assignedArbitrators;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 totalVotes;
        string resolutionReason;
        bytes32 resolutionHash;
    }

    struct ArbitratorVote {
        bool hasVoted;
        bool supportsChallenger;
        uint256 timestamp;
        string reasoning;
        uint256 confidence;
    }

    struct DisputeEvidence {
        address submitter;
        string evidenceType;
        string evidenceUri;
        bytes32 evidenceHash;
        uint256 submittedAt;
        string description;
    }

    struct ArbitratorStats {
        uint256 totalCases;
        uint256 correctDecisions;
        uint256 reputation;
        bool isActive;
        uint256 joinedAt;
    }

    mapping(uint256 => Dispute) internal disputes; // Was public
    mapping(uint256 => mapping(address => ArbitratorVote)) public arbitratorVotes;
    mapping(uint256 => DisputeEvidence[]) public disputeEvidence;
    mapping(address => uint256[]) public userDisputes;
    mapping(address => uint256[]) public challengerDisputes;
    mapping(address => uint256[]) public respondentDisputes;
    mapping(address => ArbitratorStats) public arbitratorStats;
    mapping(address => bool) public isArbitrator;

    uint256 public disputeCounter;
    address[] public activeArbitrators;
    IVerificationLogger public verificationLogger;
    IEconomicIncentives public economicIncentives;
    ITrustScore public trustScore;

    uint256 public challengeBondAmount;
    uint256 public reviewPeriod;
    uint256 public votingPeriod;
    uint256 public executionPeriod;
    uint256 public minArbitrators;
    uint256 public maxArbitrators;
    uint256 public requiredArbitratorTrustScore;

    event DisputeCreated(
        uint256 indexed disputeId, address indexed challenger, address indexed respondent, DisputeType disputeType
    );
    event EvidenceSubmitted(uint256 indexed disputeId, address indexed submitter, string evidenceType);
    event ArbitratorsAssigned(uint256 indexed disputeId, address[] arbitrators);
    event ArbitratorVoted(
        uint256 indexed disputeId, address indexed arbitrator, bool supportsChallenger, uint256 confidence
    );
    event DisputeResolved(uint256 indexed disputeId, bool challengerWon, string reason);
    event DisputeExecuted(uint256 indexed disputeId, address indexed executor);
    event DisputeAppealed(uint256 indexed disputeId, address indexed appellant);
    event ArbitratorAdded(address indexed arbitrator);
    event ArbitratorRemoved(address indexed arbitrator, string reason);
    event BondClaimed(uint256 indexed disputeId, address indexed claimer, uint256 amount);

    constructor(address _verificationLogger, address _economicIncentives, address _trustScore) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DISPUTE_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        economicIncentives = IEconomicIncentives(_economicIncentives);
        trustScore = ITrustScore(_trustScore);

        challengeBondAmount = 100 * 10 ** 18;
        reviewPeriod = 7 days;
        votingPeriod = 5 days;
        executionPeriod = 3 days;
        minArbitrators = 3;
        maxArbitrators = 7;
        requiredArbitratorTrustScore = 100;
    }

    // -- Explicit Fieldwise GETTERS --
    function getDisputeHeader(uint256 disputeId)
        external
        view
        returns (
            address challenger,
            address respondent,
            DisputeType disputeType,
            string memory title,
            DisputeStatus status
        )
    {
        Dispute storage d = disputes[disputeId];
        challenger = d.challenger;
        respondent = d.respondent;
        disputeType = d.disputeType;
        title = d.title;
        status = d.status;
    }

    function getDisputeDetails(uint256 disputeId)
        external
        view
        returns (
            string memory description,
            string memory evidenceUri,
            bytes32 evidenceHash,
            uint256 createdAt,
            uint256 reviewDeadline,
            uint256 votingDeadline,
            uint256 executionDeadline
        )
    {
        Dispute storage d = disputes[disputeId];
        return (
            d.description,
            d.evidenceUri,
            d.evidenceHash,
            d.createdAt,
            d.reviewDeadline,
            d.votingDeadline,
            d.executionDeadline
        );
    }

    function getDisputeVotes(uint256 disputeId)
        external
        view
        returns (
            uint256 forVotes,
            uint256 againstVotes,
            uint256 totalVotes,
            bool challengerWon,
            string memory resolutionReason,
            bytes32 resolutionHash,
            address[] memory arbitrators
        )
    {
        Dispute storage d = disputes[disputeId];
        forVotes = d.votesFor;
        againstVotes = d.votesAgainst;
        totalVotes = d.totalVotes;
        challengerWon = d.challengerWon;
        resolutionReason = d.resolutionReason;
        resolutionHash = d.resolutionHash;
        arbitrators = d.assignedArbitrators;
    }

    // -- End GETTERS --

    // (The rest of your contract logic follows as before, always referring to 'disputes' as internal)

    // Example create/vote/resolve logic
    function createDispute(
        address respondent,
        DisputeType disputeType,
        string memory title,
        string memory description,
        string memory evidenceUri,
        bytes32 evidenceHash
    ) external nonReentrant returns (uint256) {
        require(respondent != address(0) && respondent != msg.sender, "Invalid respondent");
        require(bytes(title).length > 0, "Title required");
        require(bytes(description).length > 0, "Description required");

        disputeCounter++;
        uint256 disputeId = disputeCounter;

        Dispute storage d = disputes[disputeId];
        d.id = disputeId;
        d.challenger = msg.sender;
        d.respondent = respondent;
        d.disputeType = disputeType;
        d.title = title;
        d.description = description;
        d.evidenceUri = evidenceUri;
        d.evidenceHash = evidenceHash;
        d.challengeBond = challengeBondAmount;
        d.createdAt = block.timestamp;
        d.reviewDeadline = block.timestamp + reviewPeriod;
        d.status = DisputeStatus.Pending;

        if (bytes(evidenceUri).length > 0) {
            disputeEvidence[disputeId].push(
                DisputeEvidence({
                    submitter: msg.sender,
                    evidenceType: "initial",
                    evidenceUri: evidenceUri,
                    evidenceHash: evidenceHash,
                    submittedAt: block.timestamp,
                    description: "Initial dispute evidence"
                })
            );
        }

        userDisputes[msg.sender].push(disputeId);
        userDisputes[respondent].push(disputeId);
        challengerDisputes[msg.sender].push(disputeId);
        respondentDisputes[respondent].push(disputeId);

        _assignArbitrators(disputeId);
        trustScore.updateScore(msg.sender, -5, "Created dispute");
        verificationLogger.logEvent(
            "DISPUTE_CREATED", msg.sender, keccak256(abi.encodePacked(disputeId, title, uint256(disputeType)))
        );
        emit DisputeCreated(disputeId, msg.sender, respondent, disputeType);
        return disputeId;
    }

    function voteOnDispute(uint256 disputeId, bool supportsChallenger, string memory reasoning, uint256 confidence)
        external
        onlyRole(ARBITRATOR_ROLE)
    {
        Dispute storage d = disputes[disputeId];
        require(d.status == DisputeStatus.VotingPhase, "Not in voting phase");
        require(block.timestamp <= d.votingDeadline, "Voting period expired");
        require(_isAssignedArbitrator(disputeId, msg.sender), "Not assigned arbitrator");
        require(!arbitratorVotes[disputeId][msg.sender].hasVoted, "Already voted");
        require(confidence >= 1 && confidence <= 100, "Invalid confidence level");

        arbitratorVotes[disputeId][msg.sender] = ArbitratorVote({
            hasVoted: true,
            supportsChallenger: supportsChallenger,
            timestamp: block.timestamp,
            reasoning: reasoning,
            confidence: confidence
        });

        d.totalVotes++;
        if (supportsChallenger) d.votesFor++;
        else d.votesAgainst++;
        arbitratorStats[msg.sender].totalCases++;
        verificationLogger.logEvent(
            "ARBITRATOR_VOTED", msg.sender, keccak256(abi.encodePacked(disputeId, supportsChallenger, confidence))
        );
        emit ArbitratorVoted(disputeId, msg.sender, supportsChallenger, confidence);
        if (d.totalVotes >= minArbitrators) {
            _checkAndResolveDispute(disputeId);
        }
    }

    function _checkAndResolveDispute(uint256 disputeId) private {
        Dispute storage d = disputes[disputeId];
        if (d.totalVotes >= minArbitrators) {
            string memory reason =
                d.votesFor > d.votesAgainst ? "Majority supports challenger" : "Majority supports respondent";
            _resolveDispute(disputeId, reason);
        }
    }

    function _resolveDispute(uint256 disputeId, string memory reason) private {
        Dispute storage d = disputes[disputeId];
        d.challengerWon = d.votesFor > d.votesAgainst;
        d.status = DisputeStatus.Resolved;
        d.resolutionReason = reason;
        d.resolutionHash = keccak256(abi.encodePacked(reason, block.timestamp));
        d.executionDeadline = block.timestamp + executionPeriod;
        verificationLogger.logEvent(
            "DISPUTE_RESOLVED",
            d.challengerWon ? d.challenger : d.respondent,
            keccak256(abi.encodePacked(disputeId, d.challengerWon, reason))
        );
        emit DisputeResolved(disputeId, d.challengerWon, reason);
    }

    // ...Copy over all remaining admin/arbitrator, appeal, evidence and arbitrator stats functions just as in your original file,
    // but always use only internal disputes[disputeId] and never return a whole struct.

    function _assignArbitrators(uint256 disputeId) private {
        require(activeArbitrators.length >= minArbitrators, "Not enough arbitrators");
        Dispute storage d = disputes[disputeId];
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, disputeId, d.challenger)));
        uint256 arbitratorCount = minArbitrators;
        if (d.disputeType == DisputeType.GovernanceDispute || d.disputeType == DisputeType.TokenDispute) {
            arbitratorCount = minArbitrators + 2;
        }
        for (uint256 i = 0; i < arbitratorCount && i < activeArbitrators.length; i++) {
            uint256 index = (seed + i) % activeArbitrators.length;
            d.assignedArbitrators.push(activeArbitrators[index]);
        }
        d.status = DisputeStatus.UnderReview;
        emit ArbitratorsAssigned(disputeId, d.assignedArbitrators);
    }

    function _isAssignedArbitrator(uint256 disputeId, address arbitrator) private view returns (bool) {
        Dispute storage d = disputes[disputeId];
        for (uint256 i = 0; i < d.assignedArbitrators.length; i++) {
            if (d.assignedArbitrators[i] == arbitrator) return true;
        }
        return false;
    }

    function _removeFromArbitratorList(address arbitrator) private {
        for (uint256 i = 0; i < activeArbitrators.length; i++) {
            if (activeArbitrators[i] == arbitrator) {
                activeArbitrators[i] = activeArbitrators[activeArbitrators.length - 1];
                activeArbitrators.pop();
                break;
            }
        }
    }
    // -- end contract --
}

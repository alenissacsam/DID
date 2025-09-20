// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IVerificationLogger.sol";

interface IEconomicIncentives {
    function getStakeInfo(
        address user
    )
        external
        view
        returns (
            uint256 amount,
            uint256 stakedAt,
            bool isActive,
            uint256 lockExpiry,
            bool isSlashed,
            uint256 tier
        );
}

contract GovernanceManager is AccessControl, ReentrancyGuard {
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    enum ProposalState {
        Pending,
        Active,
        Succeeded,
        Defeated,
        Executed,
        Cancelled,
        Expired
    }
    enum ProposalType {
        Constitutional,
        Treasury,
        Technical,
        Community
    }

    struct Proposal {
        uint256 id;
        address proposer;
        ProposalType proposalType;
        string title;
        string description;
        string metadataUri;
        bytes[] callDatas;
        address[] targets;
        uint256[] values;
        uint256 startTime;
        uint256 endTime;
        uint256 executionTime;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        ProposalState state;
        bool executed;
        uint256 quorumRequired;
        uint256 approvalThreshold;
    }

    struct Vote {
        bool hasVoted;
        uint8 support; // 0=against, 1=for, 2=abstain
        uint256 weight;
        uint256 timestamp;
        string reason;
    }

    struct GovernanceConfig {
        uint256 votingDelay;
        uint256 votingPeriod;
        uint256 executionDelay;
        uint256 proposalThreshold;
        uint256 quorumNumerator;
        uint256 approvalNumerator;
        bool emergencyPauseEnabled;
    }

    mapping(uint256 => Proposal) internal proposals; // <--- CHANGED FROM public to internal!
    mapping(uint256 => mapping(address => Vote)) public votes;
    mapping(address => uint256[]) public userProposals;
    mapping(ProposalType => GovernanceConfig) public governanceConfigs;
    uint256 public proposalCounter;
    bool public systemPaused;

    ITrustScore public trustScore;
    IVerificationLogger public verificationLogger;
    IEconomicIncentives public economicIncentives;

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        ProposalType proposalType,
        string title
    );
    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        uint8 support,
        uint256 weight,
        string reason
    );
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId, string reason);
    event ProposalStateChanged(
        uint256 indexed proposalId,
        ProposalState newState
    );
    event GovernanceConfigUpdated(
        ProposalType proposalType,
        string parameter,
        uint256 newValue
    );
    event SystemPaused(address indexed pauser, string reason);
    event SystemUnpaused(address indexed unpauser);

    constructor(
        address _trustScore,
        address _verificationLogger,
        address _economicIncentives
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GOVERNOR_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);

        trustScore = ITrustScore(_trustScore);
        verificationLogger = IVerificationLogger(_verificationLogger);
        economicIncentives = IEconomicIncentives(_economicIncentives);
        _initializeGovernanceConfigs();
    }

    function createProposal(
        ProposalType proposalType,
        string memory title,
        string memory description,
        string memory metadataUri,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas
    ) external nonReentrant returns (uint256) {
        require(!systemPaused, "System is paused");
        require(bytes(title).length > 0, "Title required");
        require(
            targets.length == values.length &&
                values.length == callDatas.length,
            "Arrays length mismatch"
        );

        GovernanceConfig memory config = governanceConfigs[proposalType];
        uint256 proposerWeight = getVotingWeight(msg.sender);
        require(
            proposerWeight >= config.proposalThreshold,
            "Insufficient voting weight"
        );

        proposalCounter++;
        uint256 proposalId = proposalCounter;
        uint256 startTime = block.timestamp + config.votingDelay;
        uint256 endTime = startTime + config.votingPeriod;

        Proposal storage prop = proposals[proposalId];
        prop.id = proposalId;
        prop.proposer = msg.sender;
        prop.proposalType = proposalType;
        prop.title = title;
        prop.description = description;
        prop.metadataUri = metadataUri;
        prop.callDatas = callDatas;
        prop.targets = targets;
        prop.values = values;
        prop.startTime = startTime;
        prop.endTime = endTime;
        prop.executionTime = 0;
        prop.forVotes = 0;
        prop.againstVotes = 0;
        prop.abstainVotes = 0;
        prop.state = ProposalState.Pending;
        prop.executed = false;
        prop.quorumRequired = config.quorumNumerator;
        prop.approvalThreshold = config.approvalNumerator;

        userProposals[msg.sender].push(proposalId);

        trustScore.updateScore(msg.sender, 5, "Created governance proposal");
        verificationLogger.logEvent(
            "GOVERNANCE_PROPOSAL_CREATED",
            msg.sender,
            keccak256(
                abi.encodePacked(proposalId, title, uint256(proposalType))
            )
        );
        emit ProposalCreated(proposalId, msg.sender, proposalType, title);
        return proposalId;
    }

    function getProposalMeta(
        uint256 proposalId
    )
        external
        view
        returns (
            uint256 id,
            address proposer,
            ProposalType proposalType,
            string memory title,
            string memory description,
            string memory metadataUri
        )
    {
        Proposal storage prop = proposals[proposalId];
        id = prop.id;
        proposer = prop.proposer;
        proposalType = prop.proposalType;
        title = prop.title;
        description = prop.description;
        metadataUri = prop.metadataUri;
    }

    function getProposalVoting(
        uint256 proposalId
    )
        external
        view
        returns (
            uint256 startTime,
            uint256 endTime,
            uint256 forVotes,
            uint256 againstVotes,
            uint256 abstainVotes,
            ProposalState state,
            bool executed,
            uint256 quorumRequired,
            uint256 approvalThreshold
        )
    {
        Proposal storage prop = proposals[proposalId];
        startTime = prop.startTime;
        endTime = prop.endTime;
        forVotes = prop.forVotes;
        againstVotes = prop.againstVotes;
        abstainVotes = prop.abstainVotes;
        state = prop.state;
        executed = prop.executed;
        quorumRequired = prop.quorumRequired;
        approvalThreshold = prop.approvalThreshold;
    }

    // Add more getters as necessary for other slices of the Proposal struct

    function getVotingWeight(address user) public view returns (uint256) {
        uint256 trustScoreWeight = trustScore.getTrustScore(user);
        (, , bool isActive, , , uint256 tier) = economicIncentives.getStakeInfo(
            user
        );

        uint256 stakingMultiplier = isActive ? (100 + (tier * 25)) : 100;
        uint256 weight = (trustScoreWeight * stakingMultiplier) / 100;
        return weight < 10 ? 10 : weight;
    }

    // ...Rest of your existing governance contract logic unchanged; avoid returning/copying full Proposal structs...

    // Default config initialization
    function _initializeGovernanceConfigs() private {
        governanceConfigs[ProposalType.Constitutional] = GovernanceConfig({
            votingDelay: 3 days,
            votingPeriod: 7 days,
            executionDelay: 7 days,
            proposalThreshold: 100, // High trust score required
            quorumNumerator: 2000, // 20% quorum
            approvalNumerator: 7500, // 75% approval
            emergencyPauseEnabled: false
        });
        governanceConfigs[ProposalType.Treasury] = GovernanceConfig({
            votingDelay: 2 days,
            votingPeriod: 5 days,
            executionDelay: 3 days,
            proposalThreshold: 75,
            quorumNumerator: 1500, // 15% quorum
            approvalNumerator: 6000, // 60% approval
            emergencyPauseEnabled: false
        });
        governanceConfigs[ProposalType.Technical] = GovernanceConfig({
            votingDelay: 1 days,
            votingPeriod: 5 days,
            executionDelay: 2 days,
            proposalThreshold: 50,
            quorumNumerator: 1000, // 10% quorum
            approvalNumerator: 5500, // 55% approval
            emergencyPauseEnabled: true
        });
        governanceConfigs[ProposalType.Community] = GovernanceConfig({
            votingDelay: 1 days,
            votingPeriod: 3 days,
            executionDelay: 1 days,
            proposalThreshold: 25,
            quorumNumerator: 500, // 5% quorum
            approvalNumerator: 5000, // 50% approval
            emergencyPauseEnabled: false
        });
    }
}

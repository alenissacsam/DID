// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IEntryPoint.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IVerificationLogger.sol";

/**
 * @title AlchemyGasManager
 * @notice Alchemy-compatible gas manager with EduCert trust score integration
 * @dev Implements Alchemy's gas manager interface while adding trust-based sponsorship rules
 */
contract AlchemyGasManager is AccessControl, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Alchemy Gas Manager compatibility
    address public immutable entryPoint;
    ITrustScore public trustScore;
    IVerificationLogger public verificationLogger;

    // Gas sponsorship rules
    struct SponsorshipRule {
        uint256 minTrustScore; // Minimum trust score required
        uint256 maxGasPerOp; // Max gas per operation
        uint256 maxGasPerDay; // Max gas per user per day
        uint256 maxGasPerMonth; // Max gas per user per month
        bool isActive; // Rule is active
        string description; // Rule description
    }

    // Alchemy integration settings
    struct AlchemyConfig {
        string policyId; // Alchemy policy ID
        string appId; // Alchemy app ID
        address alchemyPaymaster; // Alchemy paymaster address
        bool useAlchemyBackend; // Use Alchemy's backend for gas estimation
        uint256 maxSponsoredGas; // Max gas to sponsor via Alchemy
    }

    // State variables
    AlchemyConfig public alchemyConfig;
    mapping(bytes32 => SponsorshipRule) public sponsorshipRules;
    mapping(address => mapping(uint256 => uint256)) public dailyGasUsed; // user => day => gas
    mapping(address => mapping(uint256 => uint256)) public monthlyGasUsed; // user => month => gas
    mapping(address => uint256) public totalGasSponsored;
    mapping(address => bool) public whitelistedDApps;

    // Onboarding support
    mapping(address => uint256) public userOnboardingStart;
    mapping(address => uint256) public onboardingGasUsed;
    uint256 public onboardingGasAllowance;
    uint256 public onboardingPeriod;

    // Events
    event GasSponsored(
        address indexed user,
        address indexed dapp,
        uint256 gasAmount,
        uint256 trustScore,
        string ruleUsed
    );
    event SponsorshipRuleUpdated(
        bytes32 indexed ruleId,
        uint256 minTrustScore,
        uint256 maxGasPerOp,
        bool isActive
    );
    event AlchemyConfigUpdated(
        string policyId,
        string appId,
        address paymaster
    );
    event OnboardingGasProvided(
        address indexed user,
        uint256 gasAmount,
        uint256 remainingAllowance
    );

    constructor(
        address _entryPoint,
        address _trustScore,
        address _verificationLogger,
        string memory _alchemyPolicyId,
        string memory _alchemyAppId,
        address _alchemyPaymaster
    ) {
        require(_entryPoint != address(0), "Invalid EntryPoint");
        require(_trustScore != address(0), "Invalid TrustScore");
        require(
            _verificationLogger != address(0),
            "Invalid VerificationLogger"
        );

        entryPoint = _entryPoint;
        trustScore = ITrustScore(_trustScore);
        verificationLogger = IVerificationLogger(_verificationLogger);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Set up Alchemy configuration
        alchemyConfig = AlchemyConfig({
            policyId: _alchemyPolicyId,
            appId: _alchemyAppId,
            alchemyPaymaster: _alchemyPaymaster,
            useAlchemyBackend: true,
            maxSponsoredGas: 10000000 // 10M gas max
        });

        // Default onboarding settings
        onboardingGasAllowance = 2000000; // 2M gas for new users
        onboardingPeriod = 7 days;

        // Set up default sponsorship rules
        _setupDefaultRules();
    }

    /**
     * @dev Main function to check if gas should be sponsored (Alchemy compatible)
     * @param user The user requesting gas sponsorship
     * @param gasRequested Amount of gas requested
     * @return shouldSponsor Whether to sponsor the gas
     * @return maxGas Maximum gas to sponsor
     * @return ruleUsed The rule that was applied
     */
    function shouldSponsorGas(
        address user,
        address,
        /*dapp*/ uint256 gasRequested
    )
        external
        view
        returns (bool shouldSponsor, uint256 maxGas, string memory ruleUsed)
    {
        // Check onboarding eligibility first
        if (_isUserOnboarding(user)) {
            uint256 remainingOnboarding = onboardingGasAllowance -
                onboardingGasUsed[user];
            if (remainingOnboarding >= gasRequested) {
                return (true, gasRequested, "ONBOARDING");
            }
        }

        // Check trust score based rules
        uint256 userTrustScore = trustScore.getTrustScore(user);

        // Check each rule
        bytes32[] memory ruleIds = _getActiveRuleIds();
        for (uint256 i = 0; i < ruleIds.length; i++) {
            bytes32 ruleId = ruleIds[i];
            SponsorshipRule memory rule = sponsorshipRules[ruleId];

            if (!rule.isActive) continue;
            if (userTrustScore < rule.minTrustScore) continue;
            if (gasRequested > rule.maxGasPerOp) continue;

            // Check daily and monthly limits
            uint256 currentDay = block.timestamp / 1 days;
            uint256 currentMonth = block.timestamp / 30 days;

            if (
                dailyGasUsed[user][currentDay] + gasRequested >
                rule.maxGasPerDay
            ) continue;
            if (
                monthlyGasUsed[user][currentMonth] + gasRequested >
                rule.maxGasPerMonth
            ) continue;

            return (true, gasRequested, rule.description);
        }

        return (false, 0, "NO_RULE_MATCHED");
    }

    /**
     * @dev Execute gas sponsorship after UserOp execution
     */
    function recordGasSponsorship(
        address user,
        address dapp,
        uint256 gasUsed,
        string memory ruleUsed
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        uint256 currentDay = block.timestamp / 1 days;
        uint256 currentMonth = block.timestamp / 30 days;

        // Update tracking
        dailyGasUsed[user][currentDay] += gasUsed;
        monthlyGasUsed[user][currentMonth] += gasUsed;
        totalGasSponsored[user] += gasUsed;

        // Handle onboarding tracking
        if (
            keccak256(abi.encodePacked(ruleUsed)) ==
            keccak256(abi.encodePacked("ONBOARDING"))
        ) {
            if (userOnboardingStart[user] == 0) {
                userOnboardingStart[user] = block.timestamp;
            }
            onboardingGasUsed[user] += gasUsed;

            emit OnboardingGasProvided(
                user,
                gasUsed,
                onboardingGasAllowance - onboardingGasUsed[user]
            );
        } else {
            // Update trust score for responsible usage
            trustScore.updateScoreForGaslessTransaction(user);
        }

        // Log the sponsorship
        verificationLogger.logEvent(
            "GAS_SPONSORED",
            user,
            keccak256(abi.encodePacked(dapp, gasUsed, ruleUsed))
        );

        emit GasSponsored(
            user,
            dapp,
            gasUsed,
            trustScore.getTrustScore(user),
            ruleUsed
        );
    }

    /**
     * @dev Get Alchemy-compatible paymaster data
     */
    function getPaymasterData(
        address user,
        address dapp,
        uint256 gasLimit
    ) external view returns (bytes memory paymasterData) {
        (bool shouldSponsor, uint256 maxGas, string memory ruleUsed) = this
            .shouldSponsorGas(user, dapp, gasLimit);

        if (!shouldSponsor) {
            return "";
        }

        // Format paymaster data for Alchemy compatibility
        return
            abi.encodePacked(
                alchemyConfig.alchemyPaymaster,
                maxGas,
                keccak256(abi.encodePacked(ruleUsed))
            );
    }

    function _isUserOnboarding(address user) internal view returns (bool) {
        if (userOnboardingStart[user] == 0) return true; // First time user
        return
            (block.timestamp - userOnboardingStart[user]) <= onboardingPeriod;
    }

    function _getActiveRuleIds() internal pure returns (bytes32[] memory) {
        bytes32[] memory rules = new bytes32[](4);
        rules[0] = keccak256("HIGH_TRUST");
        rules[1] = keccak256("MEDIUM_TRUST");
        rules[2] = keccak256("LOW_TRUST");
        rules[3] = keccak256("BASIC_USER");
        return rules;
    }

    function _setupDefaultRules() internal {
        // High trust users (90+ score)
        sponsorshipRules[keccak256("HIGH_TRUST")] = SponsorshipRule({
            minTrustScore: 90,
            maxGasPerOp: 1000000, // 1M gas per op
            maxGasPerDay: 10000000, // 10M gas per day
            maxGasPerMonth: 200000000, // 200M gas per month
            isActive: true,
            description: "HIGH_TRUST"
        });

        // Medium trust users (50-89 score)
        sponsorshipRules[keccak256("MEDIUM_TRUST")] = SponsorshipRule({
            minTrustScore: 50,
            maxGasPerOp: 500000, // 500k gas per op
            maxGasPerDay: 5000000, // 5M gas per day
            maxGasPerMonth: 100000000, // 100M gas per month
            isActive: true,
            description: "MEDIUM_TRUST"
        });

        // Low trust users (25-49 score)
        sponsorshipRules[keccak256("LOW_TRUST")] = SponsorshipRule({
            minTrustScore: 25,
            maxGasPerOp: 250000, // 250k gas per op
            maxGasPerDay: 1000000, // 1M gas per day
            maxGasPerMonth: 20000000, // 20M gas per month
            isActive: true,
            description: "LOW_TRUST"
        });

        // Basic users (10-24 score)
        sponsorshipRules[keccak256("BASIC_USER")] = SponsorshipRule({
            minTrustScore: 10,
            maxGasPerOp: 100000, // 100k gas per op
            maxGasPerDay: 500000, // 500k gas per day
            maxGasPerMonth: 10000000, // 10M gas per month
            isActive: true,
            description: "BASIC_USER"
        });
    }

    // Admin functions
    function updateSponsorshipRule(
        string memory ruleId,
        uint256 minTrustScore,
        uint256 maxGasPerOp,
        uint256 maxGasPerDay,
        uint256 maxGasPerMonth,
        bool isActive,
        string memory description
    ) external onlyRole(ADMIN_ROLE) {
        bytes32 id = keccak256(abi.encodePacked(ruleId));
        sponsorshipRules[id] = SponsorshipRule({
            minTrustScore: minTrustScore,
            maxGasPerOp: maxGasPerOp,
            maxGasPerDay: maxGasPerDay,
            maxGasPerMonth: maxGasPerMonth,
            isActive: isActive,
            description: description
        });

        emit SponsorshipRuleUpdated(id, minTrustScore, maxGasPerOp, isActive);
    }

    function updateAlchemyConfig(
        string memory policyId,
        string memory appId,
        address alchemyPaymaster,
        uint256 maxSponsoredGas
    ) external onlyRole(ADMIN_ROLE) {
        alchemyConfig.policyId = policyId;
        alchemyConfig.appId = appId;
        alchemyConfig.alchemyPaymaster = alchemyPaymaster;
        alchemyConfig.maxSponsoredGas = maxSponsoredGas;

        emit AlchemyConfigUpdated(policyId, appId, alchemyPaymaster);
    }

    function setOnboardingSettings(
        uint256 gasAllowance,
        uint256 period
    ) external onlyRole(ADMIN_ROLE) {
        onboardingGasAllowance = gasAllowance;
        onboardingPeriod = period;
    }

    function whitelistDApp(
        address dapp,
        bool whitelisted
    ) external onlyRole(ADMIN_ROLE) {
        whitelistedDApps[dapp] = whitelisted;
    }

    // Emergency withdrawal
    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        payable(msg.sender).transfer(address(this).balance);
    }

    // Receive ETH for gas sponsorship
    receive() external payable {}
}

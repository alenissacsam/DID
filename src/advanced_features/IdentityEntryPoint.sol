// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IEntryPoint.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";

/**
 * @title IdentityEntryPoint
 * @notice Custom EntryPoint wrapper for Identity system with trust score integration
 * @dev This contract wraps the standard ERC-4337 EntryPoint with Identity-specific features
 */
contract IdentityEntryPoint is AccessControl, ReentrancyGuard {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAYMASTER_ADMIN_ROLE =
        keccak256("PAYMASTER_ADMIN_ROLE");

    // Core contracts
    IEntryPoint public immutable entryPoint;
    IVerificationLogger public verificationLogger;
    ITrustScore public trustScore;

    // Identity-specific settings
    uint256 public minTrustScoreForGasless;
    uint256 public gasSubsidyLimit; // Max gas units to subsidize per operation
    uint256 public dailyGasLimit; // Max gas units per user per day
    bool public trustScoreBasedGasSubsidy;

    // Web2 onboarding settings
    uint256 public onboardingGasAllowance; // Total gas allowance for new users
    uint256 public onboardingPeriod; // Time period for onboarding (in seconds)
    bool public enableOnboardingSubsidy; // Enable gas subsidy for new users

    // Tracking
    mapping(address => uint256) public dailyGasUsed;
    mapping(address => uint256) public lastResetDay;
    mapping(address => bool) public whitelistedPaymasters;
    mapping(address => uint256) public userGasSubsidyUsed;

    // Onboarding tracking
    mapping(address => uint256) public userFirstInteraction; // Timestamp of first interaction
    mapping(address => uint256) public onboardingGasUsed; // Gas used during onboarding period

    // Events
    event GasSubsidyApplied(
        address indexed user,
        uint256 gasAmount,
        uint256 trustScore
    );
    event OnboardingSubsidyApplied(
        address indexed user,
        uint256 gasAmount,
        uint256 remainingAllowance
    );
    event TrustScoreThresholdUpdated(
        uint256 oldThreshold,
        uint256 newThreshold
    );
    event GasLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event PaymasterWhitelisted(address indexed paymaster, bool whitelisted);
    event IdentityUserOpExecuted(
        bytes32 indexed userOpHash,
        address indexed sender,
        bool subsidized,
        uint256 trustScore,
        uint256 gasUsed
    );
    event OnboardingSettingsUpdated(
        uint256 gasAllowance,
        uint256 period,
        bool enabled
    );

    /**
     * @dev Constructor that sets up the Identity EntryPoint
     * @param _entryPoint Address of the standard ERC-4337 EntryPoint
     * @param _verificationLogger Address of the verification logger
     * @param _trustScore Address of the trust score contract
     * @param _minTrustScoreForGasless Minimum trust score for gasless operations
     * @param _gasSubsidyLimit Maximum gas subsidy per user
     * @param _dailyGasLimit Daily gas limit per user
     */
    constructor(
        address _entryPoint,
        address _verificationLogger,
        address _trustScore,
        uint256 _minTrustScoreForGasless,
        uint256 _gasSubsidyLimit,
        uint256 _dailyGasLimit
    ) {
        require(_entryPoint != address(0), "Invalid EntryPoint address");
        require(
            _verificationLogger != address(0),
            "Invalid verification logger"
        );
        require(_trustScore != address(0), "Invalid trust score");

        entryPoint = IEntryPoint(_entryPoint);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(PAYMASTER_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        trustScore = ITrustScore(_trustScore);
        minTrustScoreForGasless = _minTrustScoreForGasless;
        gasSubsidyLimit = _gasSubsidyLimit;
        dailyGasLimit = _dailyGasLimit;
        trustScoreBasedGasSubsidy = true;

        // Default onboarding settings - allow new users 2M gas over 7 days
        onboardingGasAllowance = 2000000; // 2M gas units for onboarding
        onboardingPeriod = 7 days; // 7 days onboarding period
        enableOnboardingSubsidy = true; // Enable by default
    }

    /**
     * @dev Enhanced handleOps with Identity trust score integration
     * @param ops Array of UserOperations to execute
     * @param beneficiary Address to receive gas fees
     */
    function handleOpsWithTrustScore(
        IEntryPoint.UserOperation[] calldata ops,
        address payable beneficiary
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        uint256 opsLength = ops.length;

        // Pre-process operations for trust score checks and gas subsidy eligibility
        for (uint256 i = 0; i < opsLength; i++) {
            address sender = ops[i].sender;
            uint256 userTrustScore = trustScore.getTrustScore(sender);

            // Reset daily limits if needed
            _resetDailyLimitsIfNeeded(sender);

            // Check if user is eligible for gas subsidy
            bool eligibleForSubsidy = _isEligibleForGasSubsidy(
                sender,
                userTrustScore,
                ops[i]
            );

            if (eligibleForSubsidy) {
                // Update gas tracking
                uint256 estimatedGas = ops[i].callGasLimit +
                    ops[i].verificationGasLimit +
                    ops[i].preVerificationGas;

                // Track first interaction for new users
                if (userFirstInteraction[sender] == 0) {
                    userFirstInteraction[sender] = block.timestamp;
                }

                // Check if user is in onboarding period
                bool isOnboarding = _isUserInOnboarding(sender);

                if (
                    isOnboarding &&
                    enableOnboardingSubsidy &&
                    onboardingGasUsed[sender] + estimatedGas <=
                    onboardingGasAllowance
                ) {
                    // Use onboarding allowance
                    onboardingGasUsed[sender] += estimatedGas;
                    emit OnboardingSubsidyApplied(
                        sender,
                        estimatedGas,
                        onboardingGasAllowance - onboardingGasUsed[sender]
                    );
                } else {
                    // Use regular daily allowance
                    dailyGasUsed[sender] += estimatedGas;
                    emit GasSubsidyApplied(
                        sender,
                        estimatedGas,
                        userTrustScore
                    );
                }
            }

            // Log the operation attempt
            verificationLogger.logEvent(
                "USER_OP_PROCESSED",
                sender,
                keccak256(
                    abi.encodePacked(
                        ops[i].sender,
                        ops[i].nonce,
                        userTrustScore
                    )
                )
            );
        }

        // Execute operations through standard EntryPoint
        entryPoint.handleOps(ops, beneficiary);

        // Post-process: update trust scores for successful gasless transactions
        _updateTrustScoresForGaslessOps(ops);
    }

    /**
     * @dev Check if user is eligible for gas subsidy based on trust score, onboarding status, and limits
     */
    function _isEligibleForGasSubsidy(
        address user,
        uint256 userTrustScore,
        IEntryPoint.UserOperation calldata op
    ) internal view returns (bool) {
        uint256 estimatedGas = op.callGasLimit +
            op.verificationGasLimit +
            op.preVerificationGas;

        // Check per-operation limit first (applies to all subsidized operations)
        if (estimatedGas > gasSubsidyLimit) return false;

        // Check if user is in onboarding period
        bool isOnboarding = _isUserInOnboarding(user);

        if (isOnboarding && enableOnboardingSubsidy) {
            // For onboarding users, check onboarding gas allowance
            if (
                onboardingGasUsed[user] + estimatedGas <= onboardingGasAllowance
            ) {
                return true;
            }
        }

        // Regular trust score based subsidy
        if (!trustScoreBasedGasSubsidy) return false;
        if (userTrustScore < minTrustScoreForGasless) return false;

        // Check daily limit for trust score based subsidy
        if (dailyGasUsed[user] + estimatedGas > dailyGasLimit) return false;

        return true;
    }

    /**
     * @dev Check if user is in onboarding period
     */
    function _isUserInOnboarding(address user) internal view returns (bool) {
        if (userFirstInteraction[user] == 0) return true; // First time user
        return
            (block.timestamp - userFirstInteraction[user]) <= onboardingPeriod;
    }

    /**
     * @dev Reset daily gas limits if a new day has started
     */
    function _resetDailyLimitsIfNeeded(address user) internal {
        uint256 currentDay = block.timestamp / 1 days;
        if (lastResetDay[user] < currentDay) {
            dailyGasUsed[user] = 0;
            lastResetDay[user] = currentDay;
        }
    }

    /**
     * @dev Update trust scores for users who used gasless transactions
     */
    function _updateTrustScoresForGaslessOps(
        IEntryPoint.UserOperation[] calldata ops
    ) internal {
        for (uint256 i = 0; i < ops.length; i++) {
            address sender = ops[i].sender;
            uint256 userTrustScore = trustScore.getTrustScore(sender);

            if (userTrustScore >= minTrustScoreForGasless) {
                // Reward trust score for using gasless transaction responsibly
                trustScore.updateScoreForGaslessTransaction(sender);

                emit IdentityUserOpExecuted(
                    entryPoint.getUserOpHash(ops[i]),
                    sender,
                    true, // subsidized
                    userTrustScore,
                    ops[i].callGasLimit +
                        ops[i].verificationGasLimit +
                        ops[i].preVerificationGas
                );
            }
        }
    }

    /**
     * @dev Fallback to standard EntryPoint handleOps for non-Identity operations
     */
    function handleOps(
        IEntryPoint.UserOperation[] calldata ops,
        address payable beneficiary
    ) external onlyRole(OPERATOR_ROLE) {
        entryPoint.handleOps(ops, beneficiary);
    }

    /**
     * @dev Get user operation hash through EntryPoint
     */
    function getUserOpHash(
        IEntryPoint.UserOperation calldata userOp
    ) external view returns (bytes32) {
        return entryPoint.getUserOpHash(userOp);
    }

    /**
     * @dev Get nonce through EntryPoint
     */
    function getNonce(
        address sender,
        uint192 key
    ) external view returns (uint256) {
        return entryPoint.getNonce(sender, key);
    }

    /**
     * @dev Deposit ETH for gas fees through EntryPoint
     */
    function depositTo(address account) external payable {
        entryPoint.depositTo{value: msg.value}(account);
    }

    /**
     * @dev Get balance through EntryPoint
     */
    function balanceOf(address account) external view returns (uint256) {
        return entryPoint.balanceOf(account);
    }

    /**
     * @dev Check if user is eligible for gas subsidy (view function)
     */
    function isEligibleForGasSubsidy(
        address user
    ) external view returns (bool eligible, string memory reason) {
        uint256 userTrustScore = trustScore.getTrustScore(user);

        // Check onboarding eligibility first
        bool isOnboarding = _isUserInOnboarding(user);

        if (isOnboarding && enableOnboardingSubsidy) {
            if (onboardingGasUsed[user] < onboardingGasAllowance) {
                return (true, "Eligible for onboarding gas subsidy");
            } else {
                return (false, "Onboarding gas allowance exhausted");
            }
        }

        // Check trust score based eligibility
        if (!trustScoreBasedGasSubsidy) {
            return (false, "Gas subsidy disabled");
        }

        if (userTrustScore < minTrustScoreForGasless) {
            return (false, "Trust score too low");
        }

        // Check daily limit (simulate reset)
        uint256 currentDay = block.timestamp / 1 days;
        uint256 currentDailyUsage = (lastResetDay[user] < currentDay)
            ? 0
            : dailyGasUsed[user];

        if (currentDailyUsage >= dailyGasLimit) {
            return (false, "Daily gas limit exceeded");
        }

        return (true, "Eligible for trust score based gas subsidy");
    }

    /**
     * @dev Get user's onboarding status and remaining allowance
     */
    function getUserOnboardingInfo(
        address user
    )
        external
        view
        returns (
            bool isOnboarding,
            uint256 gasUsed,
            uint256 gasRemaining,
            uint256 timeRemaining
        )
    {
        isOnboarding = _isUserInOnboarding(user);
        gasUsed = onboardingGasUsed[user];
        gasRemaining = (gasUsed >= onboardingGasAllowance)
            ? 0
            : onboardingGasAllowance - gasUsed;

        if (userFirstInteraction[user] == 0 || isOnboarding) {
            uint256 elapsed = (userFirstInteraction[user] == 0)
                ? 0
                : block.timestamp - userFirstInteraction[user];
            timeRemaining = (elapsed >= onboardingPeriod)
                ? 0
                : onboardingPeriod - elapsed;
        } else {
            timeRemaining = 0;
        }
    }

    // Admin functions
    function setTrustScoreThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldThreshold = minTrustScoreForGasless;
        minTrustScoreForGasless = newThreshold;
        emit TrustScoreThresholdUpdated(oldThreshold, newThreshold);
    }

    function setGasSubsidyLimit(
        uint256 newLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldLimit = gasSubsidyLimit;
        gasSubsidyLimit = newLimit;
        emit GasLimitUpdated(oldLimit, newLimit);
    }

    function setDailyGasLimit(
        uint256 newLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldLimit = dailyGasLimit;
        dailyGasLimit = newLimit;
        emit GasLimitUpdated(oldLimit, newLimit);
    }

    function setTrustScoreBasedGasSubsidy(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        trustScoreBasedGasSubsidy = enabled;
    }

    function whitelistPaymaster(
        address paymaster,
        bool whitelisted
    ) external onlyRole(PAYMASTER_ADMIN_ROLE) {
        whitelistedPaymasters[paymaster] = whitelisted;
        emit PaymasterWhitelisted(paymaster, whitelisted);
    }

    // Onboarding configuration functions
    function setOnboardingSettings(
        uint256 _gasAllowance,
        uint256 _period,
        bool _enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        onboardingGasAllowance = _gasAllowance;
        onboardingPeriod = _period;
        enableOnboardingSubsidy = _enabled;
        emit OnboardingSettingsUpdated(_gasAllowance, _period, _enabled);
    }

    function setOnboardingGasAllowance(
        uint256 _gasAllowance
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        onboardingGasAllowance = _gasAllowance;
        emit OnboardingSettingsUpdated(
            _gasAllowance,
            onboardingPeriod,
            enableOnboardingSubsidy
        );
    }

    function setOnboardingPeriod(
        uint256 _period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        onboardingPeriod = _period;
        emit OnboardingSettingsUpdated(
            onboardingGasAllowance,
            _period,
            enableOnboardingSubsidy
        );
    }

    function setEnableOnboardingSubsidy(
        bool _enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        enableOnboardingSubsidy = _enabled;
        emit OnboardingSettingsUpdated(
            onboardingGasAllowance,
            onboardingPeriod,
            _enabled
        );
    }

    // Emergency functions
    function emergencyWithdraw(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "No balance to withdraw");
        to.transfer(balance);
    }

    // Allow contract to receive ETH for gas subsidies
    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IUserIdentityRegistry.sol";

contract PaymasterManager is AccessControl, ReentrancyGuard {
    bytes32 public constant PAYMASTER_ADMIN_ROLE = keccak256("PAYMASTER_ADMIN_ROLE");
    bytes32 public constant SPONSOR_ROLE = keccak256("SPONSOR_ROLE");

    enum SponsorshipType {
        TrustBased, // Based on user trust score
        Educational, // For educational institutions
        Promotional, // Promotional gasless transactions
        Community, // Community-sponsored
        Premium, // Premium subscription
        Emergency // Emergency transactions

    }

    enum PaymasterStatus {
        Active,
        Paused,
        Deprecated,
        OutOfFunds
    }

    struct SponsorshipPolicy {
        SponsorshipType sponsorType;
        uint256 minTrustScore;
        uint256 dailyLimit; // Per user per day
        uint256 monthlyLimit; // Per user per month
        uint256 maxGasPrice; // Maximum gas price to sponsor
        uint256 maxGasLimit; // Maximum gas limit to sponsor
        bool requiresVerification; // Requires identity verification
        uint256 verificationLevel; // Required verification level (0-3)
        uint256 costPerTx; // Cost per transaction in tokens
        bool isActive;
        uint256 createdAt;
        uint256 updatedAt;
        string[] allowedFunctions; // Specific functions to sponsor
        address[] allowedContracts; // Specific contracts to sponsor
    }

    struct UserQuota {
        uint256 dailyUsed;
        uint256 monthlyUsed;
        uint256 lastResetDay;
        uint256 lastResetMonth;
        uint256 totalTransactions;
        uint256 totalGasSponsored;
        bool isPremiumUser;
        uint256 premiumExpiresAt;
    }

    struct SponsorPool {
        address sponsor;
        string poolName;
        uint256 totalFunds;
        uint256 usedFunds;
        uint256 reservedFunds;
        SponsorshipType[] supportedTypes;
        bool isActive;
        uint256 createdAt;
        uint256 expiresAt;
        mapping(address => bool) authorizedUsers;
        mapping(SponsorshipType => uint256) typeAllocations;
    }

    struct TransactionSponsorship {
        address user;
        address wallet;
        bytes32 userOpHash;
        uint256 gasUsed;
        uint256 gasPrice;
        uint256 totalCost;
        SponsorshipType sponsorType;
        address sponsorPool;
        uint256 timestamp;
        bool isRefunded;
        string transactionType;
    }

    mapping(SponsorshipType => SponsorshipPolicy) public sponsorshipPolicies;
    mapping(address => mapping(SponsorshipType => UserQuota)) public userQuotas;
    mapping(address => SponsorPool) public sponsorPools;
    mapping(bytes32 => TransactionSponsorship) public sponsoredTransactions;
    mapping(address => bytes32[]) public userSponsoredTxs;
    mapping(address => bool) public premiumUsers;
    mapping(address => uint256) public userCreditBalance; // Token credits for gasless txs

    address[] public allSponsorPools;
    bytes32[] public allSponsoredTxs;
    uint256 public sponsorshipCounter;

    IVerificationLogger public verificationLogger;
    ITrustScore public trustScore;
    IUserIdentityRegistry public userRegistry;

    // Global settings
    uint256 public maxDailyGasPerUser;
    uint256 public maxMonthlyGasPerUser;
    uint256 public emergencyGasReserve;
    PaymasterStatus public paymasterStatus;
    uint256 public tokenToGasRate; // How many tokens equal 1 unit of gas

    event TransactionSponsored(
        bytes32 indexed userOpHash, address indexed user, SponsorshipType sponsorType, uint256 gasCost
    );
    event SponsorPoolCreated(address indexed sponsor, string poolName, uint256 initialFunds);
    event SponsorPoolFunded(address indexed pool, uint256 amount, address funder);
    event UserQuotaExceeded(address indexed user, SponsorshipType sponsorType, uint256 limit);
    event PolicyUpdated(SponsorshipType indexed sponsorType, uint256 minTrustScore, uint256 dailyLimit);
    event PremiumUserAdded(address indexed user, uint256 expiresAt);
    event PaymasterStatusChanged(PaymasterStatus oldStatus, PaymasterStatus newStatus);
    event EmergencyWithdrawal(address indexed admin, uint256 amount);

    constructor(address _verificationLogger, address _trustScore, address _userRegistry) {
        require(_verificationLogger != address(0), "Invalid verification logger");
        require(_trustScore != address(0), "Invalid trust score");
        require(_userRegistry != address(0), "Invalid user registry");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAYMASTER_ADMIN_ROLE, msg.sender);
        _grantRole(SPONSOR_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        trustScore = ITrustScore(_trustScore);
        userRegistry = IUserIdentityRegistry(_userRegistry);

        maxDailyGasPerUser = 0.01 ether;
        maxMonthlyGasPerUser = 0.1 ether;
        emergencyGasReserve = 1 ether;
        paymasterStatus = PaymasterStatus.Active;
        tokenToGasRate = 100; // 100 tokens = 1 unit gas

        _initializePolicies();
    }

    function sponsorTransaction(
        address user,
        address wallet,
        bytes32 userOpHash,
        uint256 gasUsed,
        uint256 gasPrice,
        string memory transactionType,
        SponsorshipType sponsorType
    ) external onlyRole(SPONSOR_ROLE) nonReentrant returns (bool) {
        require(user != address(0), "Invalid user");
        require(wallet != address(0), "Invalid wallet");
        require(userOpHash != bytes32(0), "Invalid user op hash");
        require(gasUsed > 0 && gasPrice > 0, "Invalid gas parameters");
        require(bytes(transactionType).length > 0, "Empty transaction type");
        require(paymasterStatus == PaymasterStatus.Active, "Paymaster not active");

        SponsorshipPolicy memory policy = sponsorshipPolicies[sponsorType];
        require(policy.isActive, "Sponsorship type not active");

        // Check eligibility
        if (!_checkEligibility(user, sponsorType, gasUsed, gasPrice)) {
            return false;
        }

        uint256 totalCost = gasUsed * gasPrice;

        // Check and update quotas
        if (!_checkAndUpdateQuota(user, sponsorType, totalCost)) {
            emit UserQuotaExceeded(user, sponsorType, policy.dailyLimit);
            return false;
        }

        // Deduct from appropriate pool or credits
        address selectedPool = _selectSponsorPool(sponsorType, totalCost);
        if (selectedPool == address(0) && userCreditBalance[user] < totalCost) {
            return false; // No funding available
        }

        if (selectedPool != address(0)) {
            sponsorPools[selectedPool].usedFunds += totalCost;
        } else {
            userCreditBalance[user] -= totalCost;
        }

        // Record the sponsorship
        sponsorshipCounter++;
        bytes32 sponsorshipId = keccak256(abi.encodePacked(userOpHash, sponsorshipCounter));

        sponsoredTransactions[sponsorshipId] = TransactionSponsorship({
            user: user,
            wallet: wallet,
            userOpHash: userOpHash,
            gasUsed: gasUsed,
            gasPrice: gasPrice,
            totalCost: totalCost,
            sponsorType: sponsorType,
            sponsorPool: selectedPool,
            timestamp: block.timestamp,
            isRefunded: false,
            transactionType: transactionType
        });

        userSponsoredTxs[user].push(sponsorshipId);
        allSponsoredTxs.push(sponsorshipId);

        // Log the event
        verificationLogger.logEvent(
            "TRANSACTION_SPONSORED", user, keccak256(abi.encodePacked(userOpHash, uint256(sponsorType), totalCost))
        );

        emit TransactionSponsored(userOpHash, user, sponsorType, totalCost);
        return true;
    }

    function createSponsorPool(
        string memory poolName,
        uint256 initialFunding,
        SponsorshipType[] memory supportedTypes,
        uint256 expirationPeriod
    ) external payable nonReentrant returns (address) {
        require(bytes(poolName).length > 0, "Empty pool name");
        require(initialFunding > 0, "Invalid initial funding");
        require(msg.value >= initialFunding, "Insufficient funding");
        require(supportedTypes.length > 0, "No supported types");

        address poolAddress =
            address(uint160(uint256(keccak256(abi.encodePacked(poolName, msg.sender, block.timestamp)))));

        SponsorPool storage pool = sponsorPools[poolAddress];
        pool.sponsor = msg.sender;
        pool.poolName = poolName;
        pool.totalFunds = initialFunding;
        pool.usedFunds = 0;
        pool.reservedFunds = 0;
        pool.supportedTypes = supportedTypes;
        pool.isActive = true;
        pool.createdAt = block.timestamp;
        pool.expiresAt = expirationPeriod > 0 ? block.timestamp + expirationPeriod : 0;

        // Allocate funds evenly across supported types
        uint256 allocationPerType = initialFunding / supportedTypes.length;
        for (uint256 i = 0; i < supportedTypes.length; i++) {
            pool.typeAllocations[supportedTypes[i]] = allocationPerType;
        }

        allSponsorPools.push(poolAddress);

        verificationLogger.logEvent(
            "SPONSOR_POOL_CREATED", msg.sender, keccak256(abi.encodePacked(poolAddress, poolName, initialFunding))
        );

        emit SponsorPoolCreated(msg.sender, poolName, initialFunding);
        return poolAddress;
    }

    function fundSponsorPool(address poolAddress, uint256 amount) external payable nonReentrant {
        require(poolAddress != address(0), "Invalid pool address");
        require(amount > 0, "Invalid amount");
        require(msg.value >= amount, "Insufficient payment");

        SponsorPool storage pool = sponsorPools[poolAddress];
        require(pool.isActive, "Pool not active");
        require(pool.sponsor == msg.sender || hasRole(SPONSOR_ROLE, msg.sender), "Not authorized");

        pool.totalFunds += amount;

        verificationLogger.logEvent("SPONSOR_POOL_FUNDED", msg.sender, keccak256(abi.encodePacked(poolAddress, amount)));

        emit SponsorPoolFunded(poolAddress, amount, msg.sender);
    }

    function addPremiumUser(address user, uint256 duration) external onlyRole(PAYMASTER_ADMIN_ROLE) {
        require(user != address(0), "Invalid user");

        uint256 expiresAt = block.timestamp + duration;
        premiumUsers[user] = true;

        UserQuota storage quota = userQuotas[user][SponsorshipType.Premium];
        quota.isPremiumUser = true;
        quota.premiumExpiresAt = expiresAt;

        verificationLogger.logEvent("PREMIUM_USER_ADDED", user, keccak256(abi.encodePacked(expiresAt)));

        emit PremiumUserAdded(user, expiresAt);
    }

    function updateSponsorshipPolicy(
        SponsorshipType sponsorType,
        uint256 minTrustScore,
        uint256 dailyLimit,
        uint256 monthlyLimit,
        uint256 maxGasPrice,
        bool requiresVerification,
        uint256 verificationLevel
    ) external onlyRole(PAYMASTER_ADMIN_ROLE) {
        SponsorshipPolicy storage policy = sponsorshipPolicies[sponsorType];

        policy.minTrustScore = minTrustScore;
        policy.dailyLimit = dailyLimit;
        policy.monthlyLimit = monthlyLimit;
        policy.maxGasPrice = maxGasPrice;
        policy.requiresVerification = requiresVerification;
        policy.verificationLevel = verificationLevel;
        policy.updatedAt = block.timestamp;

        verificationLogger.logEvent(
            "SPONSORSHIP_POLICY_UPDATED",
            msg.sender,
            keccak256(abi.encodePacked(uint256(sponsorType), minTrustScore, dailyLimit))
        );

        emit PolicyUpdated(sponsorType, minTrustScore, dailyLimit);
    }

    function pausePaymaster() external onlyRole(PAYMASTER_ADMIN_ROLE) {
        PaymasterStatus oldStatus = paymasterStatus;
        paymasterStatus = PaymasterStatus.Paused;

        emit PaymasterStatusChanged(oldStatus, PaymasterStatus.Paused);
    }

    function resumePaymaster() external onlyRole(PAYMASTER_ADMIN_ROLE) {
        PaymasterStatus oldStatus = paymasterStatus;
        paymasterStatus = PaymasterStatus.Active;

        emit PaymasterStatusChanged(oldStatus, PaymasterStatus.Active);
    }

    function emergencyWithdraw(uint256 amount, address payable recipient) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(recipient != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient balance");
        require(amount <= emergencyGasReserve, "Exceeds emergency reserve");

        (bool success,) = recipient.call{value: amount}("");
        require(success, "Withdrawal failed");

        verificationLogger.logEvent("EMERGENCY_WITHDRAWAL", msg.sender, keccak256(abi.encodePacked(amount, recipient)));

        emit EmergencyWithdrawal(msg.sender, amount);
    }

    function getUserQuota(address user, SponsorshipType sponsorType)
        external
        view
        returns (uint256 dailyUsed, uint256 monthlyUsed, uint256 dailyLimit, uint256 monthlyLimit, bool isPremiumUser)
    {
        UserQuota memory quota = userQuotas[user][sponsorType];
        SponsorshipPolicy memory policy = sponsorshipPolicies[sponsorType];

        return (quota.dailyUsed, quota.monthlyUsed, policy.dailyLimit, policy.monthlyLimit, quota.isPremiumUser);
    }

    function getSponsorPool(address poolAddress)
        external
        view
        returns (
            address sponsor,
            string memory poolName,
            uint256 totalFunds,
            uint256 usedFunds,
            uint256 availableFunds,
            bool isActive
        )
    {
        SponsorPool storage pool = sponsorPools[poolAddress];
        return (
            pool.sponsor,
            pool.poolName,
            pool.totalFunds,
            pool.usedFunds,
            pool.totalFunds - pool.usedFunds,
            pool.isActive
        );
    }

    function getUserSponsoredTransactions(address user) external view returns (bytes32[] memory) {
        return userSponsoredTxs[user];
    }

    function getUserCreditBalance(address user) external view returns (uint256) {
        return userCreditBalance[user];
    }

    function canSponsorTransaction(address user, SponsorshipType sponsorType, uint256 gasUsed, uint256 gasPrice)
        external
        view
        returns (bool, string memory)
    {
        if (paymasterStatus != PaymasterStatus.Active) {
            return (false, "Paymaster not active");
        }

        if (!_checkEligibility(user, sponsorType, gasUsed, gasPrice)) {
            return (false, "User not eligible");
        }

        uint256 totalCost = gasUsed * gasPrice;
        UserQuota memory quota = userQuotas[user][sponsorType];
        SponsorshipPolicy memory policy = sponsorshipPolicies[sponsorType];

        // Check daily limit
        uint256 currentDay = block.timestamp / 1 days;
        uint256 dailyUsed = (currentDay > quota.lastResetDay) ? 0 : quota.dailyUsed;

        if (dailyUsed + totalCost > policy.dailyLimit) {
            return (false, "Daily limit exceeded");
        }

        // Check if funding is available
        if (_selectSponsorPool(sponsorType, totalCost) == address(0) && userCreditBalance[user] < totalCost) {
            return (false, "No funding available");
        }

        return (true, "");
    }

    function getPaymasterStats()
        external
        view
        returns (
            uint256 totalSponsoredTxs,
            uint256 totalGasSponsored,
            uint256 activeSponsorPools,
            uint256 totalFundsAvailable,
            PaymasterStatus status
        )
    {
        totalSponsoredTxs = allSponsoredTxs.length;

        uint256 totalGas = 0;
        for (uint256 i = 0; i < allSponsoredTxs.length; i++) {
            totalGas += sponsoredTransactions[allSponsoredTxs[i]].totalCost;
        }
        totalGasSponsored = totalGas;

        uint256 activePools = 0;
        uint256 availableFunds = 0;
        for (uint256 i = 0; i < allSponsorPools.length; i++) {
            SponsorPool storage pool = sponsorPools[allSponsorPools[i]];
            if (pool.isActive) {
                activePools++;
                availableFunds += (pool.totalFunds - pool.usedFunds);
            }
        }

        activeSponsorPools = activePools;
        totalFundsAvailable = availableFunds;
        status = paymasterStatus;
    }

    function _checkEligibility(address user, SponsorshipType sponsorType, uint256 gasUsed, uint256 gasPrice)
        private
        view
        returns (bool)
    {
        SponsorshipPolicy memory policy = sponsorshipPolicies[sponsorType];

        // Check if user is registered
        if (!userRegistry.isRegistered(user)) return false;

        // Check gas limits
        if (gasPrice > policy.maxGasPrice || gasUsed > policy.maxGasLimit) {
            return false;
        }

        // Check trust score
        if (trustScore.getTrustScore(user) < policy.minTrustScore) return false;

        // Check verification requirements
        if (policy.requiresVerification) {
            (,,, uint256 userVerificationLevel) = userRegistry.getVerificationStatus(user);
            if (userVerificationLevel < policy.verificationLevel) return false;
        }

        // Check premium status for premium sponsorship
        if (sponsorType == SponsorshipType.Premium) {
            UserQuota memory quota = userQuotas[user][sponsorType];
            if (!quota.isPremiumUser || block.timestamp > quota.premiumExpiresAt) return false;
        }

        return true;
    }

    function _checkAndUpdateQuota(address user, SponsorshipType sponsorType, uint256 totalCost)
        private
        returns (bool)
    {
        UserQuota storage quota = userQuotas[user][sponsorType];
        SponsorshipPolicy memory policy = sponsorshipPolicies[sponsorType];

        uint256 currentDay = block.timestamp / 1 days;
        uint256 currentMonth = block.timestamp / 30 days;

        // Reset daily quota if new day
        if (currentDay > quota.lastResetDay) {
            quota.dailyUsed = 0;
            quota.lastResetDay = currentDay;
        }

        // Reset monthly quota if new month
        if (currentMonth > quota.lastResetMonth) {
            quota.monthlyUsed = 0;
            quota.lastResetMonth = currentMonth;
        }

        // Check limits
        if (quota.dailyUsed + totalCost > policy.dailyLimit) return false;
        if (quota.monthlyUsed + totalCost > policy.monthlyLimit) return false;

        // Update quotas
        quota.dailyUsed += totalCost;
        quota.monthlyUsed += totalCost;
        quota.totalTransactions++;
        quota.totalGasSponsored += totalCost;

        return true;
    }

    function _selectSponsorPool(SponsorshipType sponsorType, uint256 amount) private view returns (address) {
        for (uint256 i = 0; i < allSponsorPools.length; i++) {
            address poolAddr = allSponsorPools[i];
            SponsorPool storage pool = sponsorPools[poolAddr];

            if (!pool.isActive) continue;
            if (pool.expiresAt > 0 && block.timestamp > pool.expiresAt) {
                continue;
            }

            // Check if pool supports this sponsorship type
            bool supportsType = false;
            for (uint256 j = 0; j < pool.supportedTypes.length; j++) {
                if (pool.supportedTypes[j] == sponsorType) {
                    supportsType = true;
                    break;
                }
            }

            if (supportsType && pool.typeAllocations[sponsorType] >= amount) {
                return poolAddr;
            }
        }

        return address(0);
    }

    function _initializePolicies() private {
        // Trust-based sponsorship
        sponsorshipPolicies[SponsorshipType.TrustBased] = SponsorshipPolicy({
            sponsorType: SponsorshipType.TrustBased,
            minTrustScore: 50,
            dailyLimit: 0.001 ether,
            monthlyLimit: 0.01 ether,
            maxGasPrice: 20 gwei,
            maxGasLimit: 100000,
            requiresVerification: false,
            verificationLevel: 0,
            costPerTx: 0,
            isActive: true,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            allowedFunctions: new string[](0),
            allowedContracts: new address[](0)
        });

        // Educational institution sponsorship
        sponsorshipPolicies[SponsorshipType.Educational] = SponsorshipPolicy({
            sponsorType: SponsorshipType.Educational,
            minTrustScore: 25,
            dailyLimit: 0.002 ether,
            monthlyLimit: 0.02 ether,
            maxGasPrice: 25 gwei,
            maxGasLimit: 150000,
            requiresVerification: true,
            verificationLevel: 1,
            costPerTx: 0,
            isActive: true,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            allowedFunctions: new string[](0),
            allowedContracts: new address[](0)
        });

        // Premium sponsorship
        sponsorshipPolicies[SponsorshipType.Premium] = SponsorshipPolicy({
            sponsorType: SponsorshipType.Premium,
            minTrustScore: 0,
            dailyLimit: 0.01 ether,
            monthlyLimit: 0.1 ether,
            maxGasPrice: 50 gwei,
            maxGasLimit: 500000,
            requiresVerification: false,
            verificationLevel: 0,
            costPerTx: 0,
            isActive: true,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            allowedFunctions: new string[](0),
            allowedContracts: new address[](0)
        });
    }

    receive() external payable {}
}

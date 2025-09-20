// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IVerificationLogger.sol";

contract EconomicIncentives is AccessControl, ReentrancyGuard {
    bytes32 public constant REWARD_ADMIN_ROLE = keccak256("REWARD_ADMIN_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    struct Stake {
        uint256 amount;
        uint256 stakedAt;
        bool isActive;
        uint256 lockExpiry;
        bool isSlashed;
    }

    struct RewardPool {
        uint256 totalRewards;
        uint256 distributedRewards;
        uint256 lastUpdateTime;
        bool isActive;
        uint256 rewardRate;
    }

    struct StakingTier {
        uint256 minStake;
        uint256 multiplier;
        string name;
    }

    mapping(address => Stake) public stakes;
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public totalEarnedRewards;
    mapping(string => RewardPool) public rewardPools;
    mapping(uint256 => StakingTier) public stakingTiers;

    address[] public stakers;
    uint256 public stakingTierCount;

    IERC20 public stakingToken;
    ITrustScore public trustScore;
    IVerificationLogger public verificationLogger;

    uint256 public minimumStake;
    uint256 public slashingPercentage;
    uint256 public rewardRate;
    uint256 public totalStaked;
    uint256 public stakingLockPeriod;

    event Staked(address indexed user, uint256 amount, uint256 tier);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event Slashed(address indexed user, uint256 amount, string reason);
    event RewardDistributed(
        address indexed user,
        uint256 amount,
        string reason
    );
    event StakingTierAdded(
        uint256 tierIndex,
        uint256 minStake,
        uint256 multiplier
    );
    event RewardPoolCreated(string poolName, uint256 totalRewards);

    constructor(
        address _stakingToken,
        address _trustScore,
        address _verificationLogger
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REWARD_ADMIN_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);

        stakingToken = IERC20(_stakingToken);
        trustScore = ITrustScore(_trustScore);
        verificationLogger = IVerificationLogger(_verificationLogger);

        minimumStake = 100 * 10 ** 18; // 100 tokens
        slashingPercentage = 20; // 20%
        rewardRate = 10; // Base reward rate
        stakingLockPeriod = 7 days;

        _initializeStakingTiers();
        _initializeRewardPools();
    }

    function stake(uint256 amount) external nonReentrant {
        require(amount >= minimumStake, "Amount below minimum stake");
        require(
            stakingToken.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );

        if (!stakes[msg.sender].isActive) {
            stakers.push(msg.sender);
        }

        stakes[msg.sender].amount += amount;
        stakes[msg.sender].stakedAt = block.timestamp;
        stakes[msg.sender].isActive = true;
        stakes[msg.sender].lockExpiry = block.timestamp + stakingLockPeriod;

        totalStaked += amount;

        uint256 tier = _getStakingTier(stakes[msg.sender].amount);
        trustScore.updateScore(msg.sender, 5, "Staked tokens");

        verificationLogger.logEvent(
            "TOKENS_STAKED",
            msg.sender,
            keccak256(abi.encodePacked(amount, tier))
        );

        emit Staked(msg.sender, amount, tier);
    }

    function unstake(uint256 amount) external nonReentrant {
        require(stakes[msg.sender].isActive, "No active stake");
        require(
            stakes[msg.sender].amount >= amount,
            "Insufficient staked amount"
        );
        require(
            block.timestamp >= stakes[msg.sender].lockExpiry,
            "Stake still locked"
        );
        require(!stakes[msg.sender].isSlashed, "Cannot unstake slashed stake");

        stakes[msg.sender].amount -= amount;
        totalStaked -= amount;

        if (stakes[msg.sender].amount == 0) {
            stakes[msg.sender].isActive = false;
            _removeStaker(msg.sender);
        }

        require(stakingToken.transfer(msg.sender, amount), "Transfer failed");

        verificationLogger.logEvent(
            "TOKENS_UNSTAKED",
            msg.sender,
            keccak256(abi.encodePacked(amount))
        );

        emit Unstaked(msg.sender, amount);
    }

    function emergencyUnstake() external nonReentrant {
        require(stakes[msg.sender].isActive, "No active stake");

        uint256 amount = stakes[msg.sender].amount;
        uint256 penalty = (amount * 10) / 100; // 10% penalty for emergency unstake
        uint256 netAmount = amount - penalty;

        stakes[msg.sender].amount = 0;
        stakes[msg.sender].isActive = false;
        totalStaked -= amount;

        _removeStaker(msg.sender);

        require(
            stakingToken.transfer(msg.sender, netAmount),
            "Transfer failed"
        );

        // Penalty stays in contract
        trustScore.updateScore(msg.sender, -10, "Emergency unstake penalty");

        verificationLogger.logEvent(
            "EMERGENCY_UNSTAKE",
            msg.sender,
            keccak256(abi.encodePacked(amount, penalty))
        );

        emit Unstaked(msg.sender, netAmount);
    }

    function distributeReward(
        address recipient,
        uint256 amount,
        string memory reason
    ) external onlyRole(REWARD_ADMIN_ROLE) {
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");

        pendingRewards[recipient] += amount;
        totalEarnedRewards[recipient] += amount;

        trustScore.updateScore(recipient, 1, "Reward earned");

        verificationLogger.logEvent(
            "REWARD_DISTRIBUTED",
            recipient,
            keccak256(abi.encodePacked(amount, reason))
        );

        emit RewardDistributed(recipient, amount, reason);
    }

    function claimRewards() external nonReentrant {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "No pending rewards");

        pendingRewards[msg.sender] = 0;

        require(
            stakingToken.transfer(msg.sender, reward),
            "Reward transfer failed"
        );

        verificationLogger.logEvent(
            "REWARDS_CLAIMED",
            msg.sender,
            keccak256(abi.encodePacked(reward))
        );

        emit RewardClaimed(msg.sender, reward);
    }

    function slash(
        address user,
        string memory reason
    ) external onlyRole(SLASHER_ROLE) {
        require(stakes[user].isActive, "User not staked");
        require(!stakes[user].isSlashed, "Already slashed");

        uint256 slashAmount = (stakes[user].amount * slashingPercentage) / 100;
        stakes[user].amount -= slashAmount;
        stakes[user].isSlashed = true;
        totalStaked -= slashAmount;

        if (stakes[user].amount == 0) {
            stakes[user].isActive = false;
            _removeStaker(user);
        }

        trustScore.updateScore(user, -20, "Slashed for misbehavior");

        verificationLogger.logEvent(
            "USER_SLASHED",
            user,
            keccak256(abi.encodePacked(slashAmount, reason))
        );

        emit Slashed(user, slashAmount, reason);
    }

    function calculateReward(
        address user,
        string memory /*poolType*/
    ) external view returns (uint256) {
        if (!stakes[user].isActive) return 0;

        uint256 userTrustScore = trustScore.getTrustScore(user);
        uint256 stakingTier = _getStakingTier(stakes[user].amount);
        uint256 baseReward = rewardRate;

        // Trust score multiplier
        uint256 trustMultiplier = userTrustScore / 10;
        if (trustMultiplier == 0) trustMultiplier = 1;

        // Staking tier multiplier
        uint256 tierMultiplier = stakingTiers[stakingTier].multiplier;

        return (baseReward * trustMultiplier * tierMultiplier) / 100;
    }

    function addStakingTier(
        uint256 minStake,
        uint256 multiplier,
        string memory name
    ) external onlyRole(REWARD_ADMIN_ROLE) {
        stakingTiers[stakingTierCount] = StakingTier({
            minStake: minStake,
            multiplier: multiplier,
            name: name
        });

        emit StakingTierAdded(stakingTierCount, minStake, multiplier);
        stakingTierCount++;
    }

    function createRewardPool(
        string memory poolName,
        uint256 totalRewards,
        uint256 poolRewardRate
    ) external onlyRole(REWARD_ADMIN_ROLE) {
        rewardPools[poolName] = RewardPool({
            totalRewards: totalRewards,
            distributedRewards: 0,
            lastUpdateTime: block.timestamp,
            isActive: true,
            rewardRate: poolRewardRate
        });

        emit RewardPoolCreated(poolName, totalRewards);
    }

    function batchDistributeRewards(
        address[] memory recipients,
        uint256[] memory amounts,
        string memory reason
    ) external onlyRole(REWARD_ADMIN_ROLE) {
        require(recipients.length == amounts.length, "Arrays length mismatch");

        for (uint256 i = 0; i < recipients.length; i++) {
            if (recipients[i] != address(0) && amounts[i] > 0) {
                pendingRewards[recipients[i]] += amounts[i];
                totalEarnedRewards[recipients[i]] += amounts[i];

                emit RewardDistributed(recipients[i], amounts[i], reason);
            }
        }
    }

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
        )
    {
        Stake memory userStake = stakes[user];
        return (
            userStake.amount,
            userStake.stakedAt,
            userStake.isActive,
            userStake.lockExpiry,
            userStake.isSlashed,
            _getStakingTier(userStake.amount)
        );
    }

    function getPendingRewards(address user) external view returns (uint256) {
        return pendingRewards[user];
    }

    function getTotalStaked() external view returns (uint256) {
        return totalStaked;
    }

    function getActiveStakers() external view returns (address[] memory) {
        return stakers;
    }

    function getStakingTierInfo(
        uint256 tierIndex
    )
        external
        view
        returns (uint256 minStake, uint256 multiplier, string memory name)
    {
        StakingTier memory tier = stakingTiers[tierIndex];
        return (tier.minStake, tier.multiplier, tier.name);
    }

    function _getStakingTier(
        uint256 stakedAmount
    ) private view returns (uint256) {
        // Start from highest tier and work down
        for (uint256 i = stakingTierCount; i > 0; i--) {
            if (stakedAmount >= stakingTiers[i - 1].minStake) {
                return i - 1;
            }
        }
        return 0; // Default to lowest tier
    }

    function _initializeStakingTiers() private {
        // Bronze tier
        stakingTiers[0] = StakingTier({
            minStake: 100 * 10 ** 18,
            multiplier: 100,
            name: "Bronze"
        });

        // Silver tier
        stakingTiers[1] = StakingTier({
            minStake: 1000 * 10 ** 18,
            multiplier: 125,
            name: "Silver"
        });

        // Gold tier
        stakingTiers[2] = StakingTier({
            minStake: 10000 * 10 ** 18,
            multiplier: 150,
            name: "Gold"
        });

        stakingTierCount = 3;
    }

    function _initializeRewardPools() private {
        rewardPools["CERTIFICATE_REWARD"] = RewardPool({
            totalRewards: 1000000 * 10 ** 18,
            distributedRewards: 0,
            lastUpdateTime: block.timestamp,
            isActive: true,
            rewardRate: 100
        });

        rewardPools["GOVERNANCE_REWARD"] = RewardPool({
            totalRewards: 500000 * 10 ** 18,
            distributedRewards: 0,
            lastUpdateTime: block.timestamp,
            isActive: true,
            rewardRate: 50
        });
    }

    function _removeStaker(address staker) private {
        for (uint256 i = 0; i < stakers.length; i++) {
            if (stakers[i] == staker) {
                stakers[i] = stakers[stakers.length - 1];
                stakers.pop();
                break;
            }
        }
    }
}

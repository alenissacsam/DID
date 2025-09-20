// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/IGuardianManager.sol";
import "../interfaces/ITrustScore.sol";

interface IUserOp {
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }
}

contract AAWalletManager is AccessControl, ReentrancyGuard, IUserOp {
    bytes32 public constant WALLET_ADMIN_ROLE = keccak256("WALLET_ADMIN_ROLE");
    bytes32 public constant PAYMASTER_ROLE = keccak256("PAYMASTER_ROLE");

    enum WalletType {
        Basic, // Simple AA wallet
        Guardian, // With guardian recovery
        MultiSig, // Multi-signature wallet
        TrustBased // Trust score based permissions
    }

    enum WalletStatus {
        Active,
        Locked,
        Recovering,
        Deprecated
    }

    struct WalletConfig {
        address walletAddress;
        address owner;
        WalletType walletType;
        WalletStatus status;
        uint256 createdAt;
        uint256 lastUsed;
        bytes32 salt;
        uint256 nonce;
        bool isDeployed;
        uint256 trustScoreThreshold;
        address[] signers;
        uint256 signatureThreshold;
        uint256 dailySpendingLimit;
        uint256 spentToday;
        uint256 lastResetDay;
    }

    struct Recovery {
        uint256 id;
        address wallet;
        address newOwner;
        address[] approvedGuardians;
        uint256 requestedAt;
        uint256 executeAfter;
        bool isExecuted;
        bool isCancelled;
        string reason;
    }

    struct UserOpStats {
        uint256 totalOps;
        uint256 successfulOps;
        uint256 failedOps;
        uint256 totalGasUsed;
        uint256 totalFeesPaid;
        uint256 lastOpTimestamp;
    }

    struct SessionKey {
        address keyAddress;
        uint256 validUntil;
        uint256 spendingLimit;
        uint256 spentAmount;
        bool isActive;
        string[] allowedFunctions;
        address[] allowedContracts;
    }

    mapping(address => WalletConfig) public wallets;
    mapping(address => address) public ownerToWallet; // owner => wallet address
    mapping(bytes32 => address) public saltToWallet;
    mapping(address => Recovery[]) public recoveries;
    mapping(address => UserOpStats) public userOpStats;
    mapping(address => mapping(address => SessionKey)) public sessionKeys; // wallet => sessionKey => data
    mapping(address => address[]) public walletSessionKeys;

    uint256 public recoveryCounter;
    address[] public allWallets;

    IVerificationLogger public verificationLogger;
    IGuardianManager public guardianManager;
    ITrustScore public trustScore;

    // Wallet factory settings
    address public walletImplementation;
    address public entryPoint;
    uint256 public creationFee;
    uint256 public recoveryDelay; // Default recovery delay

    event WalletCreated(
        address indexed wallet,
        address indexed owner,
        WalletType walletType,
        bytes32 salt
    );
    event WalletDeployed(address indexed wallet, address indexed owner);
    event RecoveryRequested(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed newOwner
    );
    event RecoveryExecuted(uint256 indexed recoveryId, address indexed wallet);
    event RecoveryConfirmed(
        uint256 indexed recoveryId,
        address indexed guardian
    );
    event SessionKeyAdded(
        address indexed wallet,
        address indexed sessionKey,
        uint256 validUntil
    );
    event SessionKeyRevoked(address indexed wallet, address indexed sessionKey);
    event UserOpExecuted(
        address indexed wallet,
        bytes32 indexed userOpHash,
        bool success
    );
    event WalletStatusChanged(
        address indexed wallet,
        WalletStatus oldStatus,
        WalletStatus newStatus
    );
    event DailyLimitUpdated(address indexed wallet, uint256 newLimit);
    event SignersUpdated(
        address indexed wallet,
        address[] newSigners,
        uint256 newThreshold
    );

    constructor(
        address _verificationLogger,
        address _guardianManager,
        address _trustScore,
        address _walletImplementation,
        address _entryPoint
    ) {
        require(
            _verificationLogger != address(0),
            "Invalid verification logger"
        );
        require(_guardianManager != address(0), "Invalid guardian manager");
        require(_trustScore != address(0), "Invalid trust score");
        require(
            _walletImplementation != address(0),
            "Invalid wallet implementation"
        );
        require(_entryPoint != address(0), "Invalid entry point");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(WALLET_ADMIN_ROLE, msg.sender);
        _grantRole(PAYMASTER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        guardianManager = IGuardianManager(_guardianManager);
        trustScore = ITrustScore(_trustScore);
        walletImplementation = _walletImplementation;
        entryPoint = _entryPoint;

        creationFee = 0.001 ether;
        recoveryDelay = 2 days;
    }

    function createWallet(
        WalletType walletType,
        bytes32 salt,
        address[] memory initialSigners,
        uint256 signatureThreshold,
        uint256 trustScoreThreshold,
        uint256 dailySpendingLimit
    ) external payable nonReentrant returns (address) {
        require(msg.value >= creationFee, "Insufficient creation fee");
        require(salt != bytes32(0), "Invalid salt");
        require(
            ownerToWallet[msg.sender] == address(0),
            "Wallet already exists for user"
        );
        require(saltToWallet[salt] == address(0), "Salt already used");

        if (walletType == WalletType.MultiSig) {
            require(
                initialSigners.length >= 2,
                "MultiSig needs at least 2 signers"
            );
            require(
                signatureThreshold > 0 &&
                    signatureThreshold <= initialSigners.length,
                "Invalid threshold"
            );
        }

        address walletAddress = _computeWalletAddress(salt, msg.sender);

        wallets[walletAddress] = WalletConfig({
            walletAddress: walletAddress,
            owner: msg.sender,
            walletType: walletType,
            status: WalletStatus.Active,
            createdAt: block.timestamp,
            lastUsed: block.timestamp,
            salt: salt,
            nonce: 0,
            isDeployed: false,
            trustScoreThreshold: trustScoreThreshold,
            signers: initialSigners,
            signatureThreshold: signatureThreshold,
            dailySpendingLimit: dailySpendingLimit,
            spentToday: 0,
            lastResetDay: block.timestamp / 1 days
        });

        ownerToWallet[msg.sender] = walletAddress;
        saltToWallet[salt] = walletAddress;
        allWallets.push(walletAddress);

        // Initialize stats
        userOpStats[walletAddress] = UserOpStats({
            totalOps: 0,
            successfulOps: 0,
            failedOps: 0,
            totalGasUsed: 0,
            totalFeesPaid: 0,
            lastOpTimestamp: 0
        });

        verificationLogger.logEvent(
            "AA_WALLET_CREATED",
            msg.sender,
            keccak256(
                abi.encodePacked(walletAddress, uint256(walletType), salt)
            )
        );

        emit WalletCreated(walletAddress, msg.sender, walletType, salt);
        return walletAddress;
    }

    function deployWallet(address walletAddress) external nonReentrant {
        WalletConfig storage wallet = wallets[walletAddress];
        require(
            wallet.owner == msg.sender ||
                hasRole(WALLET_ADMIN_ROLE, msg.sender),
            "Not authorized"
        );
        require(!wallet.isDeployed, "Wallet already deployed");

        bytes memory bytecode = abi.encodePacked(
            walletImplementation,
            abi.encode(wallet.owner, wallet.signers, wallet.signatureThreshold)
        );

        address deployed = Create2.deploy(0, wallet.salt, bytecode);
        require(deployed == walletAddress, "Deployment address mismatch");

        wallet.isDeployed = true;

        verificationLogger.logEvent(
            "AA_WALLET_DEPLOYED",
            wallet.owner,
            keccak256(abi.encodePacked(walletAddress))
        );

        emit WalletDeployed(walletAddress, wallet.owner);
    }

    function executeUserOp(
        UserOperation memory userOp,
        bytes32 userOpHash
    ) external onlyRole(PAYMASTER_ROLE) nonReentrant returns (bool) {
        WalletConfig storage wallet = wallets[userOp.sender];
        require(wallet.walletAddress == userOp.sender, "Invalid wallet");
        require(wallet.status == WalletStatus.Active, "Wallet not active");

        // Validate nonce
        require(userOp.nonce == wallet.nonce, "Invalid nonce");
        wallet.nonce++;

        // Check trust score if required
        if (wallet.trustScoreThreshold > 0) {
            uint256 currentTrustScore = trustScore.getTrustScore(wallet.owner);
            require(
                currentTrustScore >= wallet.trustScoreThreshold,
                "Insufficient trust score"
            );
        }

        // Check daily spending limit
        _checkDailyLimit(userOp.sender, _estimateValue(userOp));

        // Execute the operation
        bool success = _executeOperation(userOp);

        // Update statistics
        UserOpStats storage stats = userOpStats[userOp.sender];
        stats.totalOps++;
        if (success) {
            stats.successfulOps++;
        } else {
            stats.failedOps++;
        }
        stats.totalGasUsed +=
            userOp.callGasLimit +
            userOp.verificationGasLimit +
            userOp.preVerificationGas;
        stats.lastOpTimestamp = block.timestamp;

        wallet.lastUsed = block.timestamp;

        verificationLogger.logEvent(
            "USER_OP_EXECUTED",
            wallet.owner,
            keccak256(abi.encodePacked(userOpHash, success))
        );

        emit UserOpExecuted(userOp.sender, userOpHash, success);
        return success;
    }

    function requestRecovery(
        address wallet,
        address newOwner,
        string memory reason
    ) external nonReentrant returns (uint256) {
        WalletConfig storage walletConfig = wallets[wallet];
        require(walletConfig.walletAddress == wallet, "Wallet does not exist");
        require(
            walletConfig.walletType == WalletType.Guardian,
            "Wallet does not support guardian recovery"
        );

        // Check if sender is a guardian
        require(
            guardianManager.isGuardian(walletConfig.owner, msg.sender),
            "Not a guardian"
        );

        recoveryCounter++;
        uint256 recoveryId = recoveryCounter;

        Recovery memory newRecovery = Recovery({
            id: recoveryId,
            wallet: wallet,
            newOwner: newOwner,
            approvedGuardians: new address[](1),
            requestedAt: block.timestamp,
            executeAfter: block.timestamp + recoveryDelay,
            isExecuted: false,
            isCancelled: false,
            reason: reason
        });

        newRecovery.approvedGuardians[0] = msg.sender;
        recoveries[wallet].push(newRecovery);

        // Update wallet status
        walletConfig.status = WalletStatus.Recovering;

        verificationLogger.logEvent(
            "RECOVERY_REQUESTED",
            walletConfig.owner,
            keccak256(abi.encodePacked(recoveryId, wallet, newOwner))
        );

        emit RecoveryRequested(recoveryId, wallet, newOwner);
        emit WalletStatusChanged(
            wallet,
            WalletStatus.Active,
            WalletStatus.Recovering
        );
        return recoveryId;
    }

    function confirmRecovery(uint256 recoveryId, address wallet) external {
        Recovery[] storage walletRecoveries = recoveries[wallet];
        require(
            recoveryId > 0 && recoveryId <= walletRecoveries.length,
            "Invalid recovery ID"
        );

        Recovery storage recovery = walletRecoveries[recoveryId - 1];
        require(
            !recovery.isExecuted && !recovery.isCancelled,
            "Recovery not active"
        );

        WalletConfig storage walletConfig = wallets[wallet];
        require(
            guardianManager.isGuardian(walletConfig.owner, msg.sender),
            "Not a guardian"
        );

        // Check if already approved
        for (uint256 i = 0; i < recovery.approvedGuardians.length; i++) {
            require(
                recovery.approvedGuardians[i] != msg.sender,
                "Already approved"
            );
        }

        // Add guardian approval
        address[] memory newApprovals = new address[](
            recovery.approvedGuardians.length + 1
        );
        for (uint256 i = 0; i < recovery.approvedGuardians.length; i++) {
            newApprovals[i] = recovery.approvedGuardians[i];
        }
        newApprovals[recovery.approvedGuardians.length] = msg.sender;
        recovery.approvedGuardians = newApprovals;

        verificationLogger.logEvent(
            "RECOVERY_CONFIRMED",
            msg.sender,
            keccak256(abi.encodePacked(recoveryId, wallet))
        );

        emit RecoveryConfirmed(recoveryId, msg.sender);
    }

    function executeRecovery(
        uint256 recoveryId,
        address wallet
    ) external nonReentrant {
        Recovery[] storage walletRecoveries = recoveries[wallet];
        require(
            recoveryId > 0 && recoveryId <= walletRecoveries.length,
            "Invalid recovery ID"
        );

        Recovery storage recovery = walletRecoveries[recoveryId - 1];
        require(
            !recovery.isExecuted && !recovery.isCancelled,
            "Recovery not active"
        );
        require(
            block.timestamp >= recovery.executeAfter,
            "Recovery delay not met"
        );

        WalletConfig storage walletConfig = wallets[wallet];

        // Check if enough guardians approved
        (, uint256 threshold, ) = guardianManager.getGuardianSet(
            walletConfig.owner
        );
        require(
            recovery.approvedGuardians.length >= threshold,
            "Insufficient guardian approvals"
        );

        // Execute recovery
        recovery.isExecuted = true;
        address oldOwner = walletConfig.owner;
        walletConfig.owner = recovery.newOwner;
        walletConfig.status = WalletStatus.Active;

        // Update mappings
        delete ownerToWallet[oldOwner];
        ownerToWallet[recovery.newOwner] = wallet;

        verificationLogger.logEvent(
            "RECOVERY_EXECUTED",
            recovery.newOwner,
            keccak256(abi.encodePacked(recoveryId, wallet, oldOwner))
        );

        emit RecoveryExecuted(recoveryId, wallet);
        emit WalletStatusChanged(
            wallet,
            WalletStatus.Recovering,
            WalletStatus.Active
        );
    }

    function addSessionKey(
        address wallet,
        address sessionKey,
        uint256 validUntil,
        uint256 spendingLimit,
        string[] memory allowedFunctions,
        address[] memory allowedContracts
    ) external {
        WalletConfig storage walletConfig = wallets[wallet];
        require(walletConfig.owner == msg.sender, "Not wallet owner");
        require(sessionKey != address(0), "Invalid session key");
        require(validUntil > block.timestamp, "Invalid validity period");

        sessionKeys[wallet][sessionKey] = SessionKey({
            keyAddress: sessionKey,
            validUntil: validUntil,
            spendingLimit: spendingLimit,
            spentAmount: 0,
            isActive: true,
            allowedFunctions: allowedFunctions,
            allowedContracts: allowedContracts
        });

        walletSessionKeys[wallet].push(sessionKey);

        verificationLogger.logEvent(
            "SESSION_KEY_ADDED",
            msg.sender,
            keccak256(abi.encodePacked(wallet, sessionKey, validUntil))
        );

        emit SessionKeyAdded(wallet, sessionKey, validUntil);
    }

    function revokeSessionKey(address wallet, address sessionKey) external {
        WalletConfig storage walletConfig = wallets[wallet];
        require(walletConfig.owner == msg.sender, "Not wallet owner");
        require(
            sessionKeys[wallet][sessionKey].isActive,
            "Session key not active"
        );

        sessionKeys[wallet][sessionKey].isActive = false;

        verificationLogger.logEvent(
            "SESSION_KEY_REVOKED",
            msg.sender,
            keccak256(abi.encodePacked(wallet, sessionKey))
        );

        emit SessionKeyRevoked(wallet, sessionKey);
    }

    function updateWalletSettings(
        address wallet,
        uint256 newDailyLimit,
        uint256 newTrustThreshold
    ) external {
        WalletConfig storage walletConfig = wallets[wallet];
        require(walletConfig.owner == msg.sender, "Not wallet owner");

        walletConfig.dailySpendingLimit = newDailyLimit;
        walletConfig.trustScoreThreshold = newTrustThreshold;

        verificationLogger.logEvent(
            "WALLET_SETTINGS_UPDATED",
            msg.sender,
            keccak256(
                abi.encodePacked(wallet, newDailyLimit, newTrustThreshold)
            )
        );

        emit DailyLimitUpdated(wallet, newDailyLimit);
    }

    function updateSigners(
        address wallet,
        address[] memory newSigners,
        uint256 newThreshold
    ) external {
        WalletConfig storage walletConfig = wallets[wallet];
        require(walletConfig.owner == msg.sender, "Not wallet owner");
        require(
            walletConfig.walletType == WalletType.MultiSig,
            "Not a multisig wallet"
        );
        require(newSigners.length >= 2, "Minimum 2 signers required");
        require(
            newThreshold > 0 && newThreshold <= newSigners.length,
            "Invalid threshold"
        );

        walletConfig.signers = newSigners;
        walletConfig.signatureThreshold = newThreshold;

        verificationLogger.logEvent(
            "SIGNERS_UPDATED",
            msg.sender,
            keccak256(abi.encodePacked(wallet, newSigners.length, newThreshold))
        );

        emit SignersUpdated(wallet, newSigners, newThreshold);
    }

    function getWallet(
        address walletAddress
    )
        external
        view
        returns (
            address owner,
            WalletType walletType,
            WalletStatus status,
            uint256 nonce,
            bool isDeployed,
            uint256 dailySpendingLimit,
            uint256 spentToday
        )
    {
        WalletConfig memory wallet = wallets[walletAddress];
        return (
            wallet.owner,
            wallet.walletType,
            wallet.status,
            wallet.nonce,
            wallet.isDeployed,
            wallet.dailySpendingLimit,
            wallet.spentToday
        );
    }

    function getUserWallet(address user) external view returns (address) {
        return ownerToWallet[user];
    }

    function getWalletStats(
        address wallet
    ) external view returns (UserOpStats memory) {
        return userOpStats[wallet];
    }

    function getSessionKeys(
        address wallet
    ) external view returns (address[] memory) {
        return walletSessionKeys[wallet];
    }

    function isSessionKeyValid(
        address wallet,
        address sessionKey
    ) external view returns (bool) {
        SessionKey memory key = sessionKeys[wallet][sessionKey];
        return key.isActive && block.timestamp <= key.validUntil;
    }

    function getRecoveries(address wallet) external view returns (uint256) {
        return recoveries[wallet].length;
    }

    function getAllWallets() external view returns (address[] memory) {
        return allWallets;
    }

    function _computeWalletAddress(
        bytes32 salt,
        address owner
    ) private view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            walletImplementation,
            abi.encode(owner)
        );

        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    function _executeOperation(
        UserOperation memory userOp
    ) private pure returns (bool) {
        // Enhanced execution with proper validation
        if (userOp.callData.length == 0) return false;

        // Validate gas limits are reasonable
        require(userOp.callGasLimit >= 21000, "Insufficient call gas");
        require(
            userOp.verificationGasLimit >= 100000,
            "Insufficient verification gas"
        );
        require(
            userOp.preVerificationGas >= 21000,
            "Insufficient pre-verification gas"
        );

        // Validate gas prices are within reasonable bounds
        require(
            userOp.maxFeePerGas >= userOp.maxPriorityFeePerGas,
            "Invalid gas pricing"
        );
        require(userOp.maxFeePerGas <= 1000 gwei, "Gas price too high");

        // Simulate execution success based on gas limits and validation
        // In production, this would execute the actual transaction
        return
            userOp.callGasLimit >= 21000 &&
            userOp.verificationGasLimit >= 100000;
    }

    function _checkDailyLimit(address wallet, uint256 value) private {
        WalletConfig storage walletConfig = wallets[wallet];

        if (walletConfig.dailySpendingLimit == 0) return; // No limit

        uint256 currentDay = block.timestamp / 1 days;

        // Reset daily spending if new day
        if (currentDay > walletConfig.lastResetDay) {
            walletConfig.spentToday = 0;
            walletConfig.lastResetDay = currentDay;
        }

        require(
            walletConfig.spentToday + value <= walletConfig.dailySpendingLimit,
            "Daily spending limit exceeded"
        );

        walletConfig.spentToday += value;
    }

    function _estimateValue(
        UserOperation memory userOp
    ) private pure returns (uint256) {
        // Simplified value estimation - in production would decode calldata
        return userOp.callGasLimit * userOp.maxFeePerGas;
    }

    function setCreationFee(
        uint256 newFee
    ) external onlyRole(WALLET_ADMIN_ROLE) {
        creationFee = newFee;
    }

    function setRecoveryDelay(
        uint256 newDelay
    ) external onlyRole(WALLET_ADMIN_ROLE) {
        recoveryDelay = newDelay;
    }

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(recipient != address(0), "Invalid recipient");
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to withdraw");

        (bool success, ) = recipient.call{value: balance}("");
        require(success, "Withdrawal failed");
    }

    receive() external payable {}
}

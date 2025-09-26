// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "../../interfaces/IVerificationLogger.sol";
import "../../interfaces/IGuardianManager.sol";
import "../../interfaces/ITrustScore.sol";
import {IRecoveryManager} from "../../interfaces/IRecoveryManager.sol";
import {RecoveryManager} from "../RecoveryManager.sol";
import {ISessionKeyManager} from "../../interfaces/ISessionKeyManager.sol";
import {SessionKeyManager} from "../SessionKeyManager.sol";
import {IWalletStatsManager} from "../../interfaces/IWalletStatsManager.sol";
import {WalletStatsManager} from "./WalletStatsManager.sol";

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
    // Custom errors for size reduction
    error InvalidAddress();
    error InvalidParam();
    error NotOwnerOrAdmin();
    error AlreadyDeployed();
    error NotGuardian();
    error RecoveryNotActive();
    error DelayNotMet();
    error FeeTooLow();
    error InactiveWallet();
    error LowTrust();
    error LowGas();
    error GasPricing();
    error GasPriceTooHigh();
    error NotActive();
    error InvalidRecoveryId();
    error ThresholdNotMet();
    error Mismatch();
    error InvalidRecipient();
    error NoFees();
    error WithdrawalFailed();
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

    struct UserOpStats {
        uint256 totalOps;
        uint256 successfulOps;
        uint256 failedOps;
        uint256 totalGasUsed;
        uint256 totalFeesPaid;
        uint256 lastOpTimestamp;
    }

    mapping(address => WalletConfig) public wallets;
    mapping(address => address) public ownerToWallet; // owner => wallet address
    mapping(bytes32 => address) public saltToWallet;
    IWalletStatsManager public statsManager;
    ISessionKeyManager public sessionKeyManager;
    IRecoveryManager public recoveryManager;

    uint256 public recoveryCounter;
    address[] public allWallets;

    IVerificationLogger public immutable verificationLogger;
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
    // Session key events moved to SessionKeyManager
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
        if (_verificationLogger == address(0)) revert InvalidAddress();
        if (_guardianManager == address(0)) revert InvalidAddress();
        if (_trustScore == address(0)) revert InvalidAddress();
        if (_walletImplementation == address(0)) revert InvalidAddress();
        if (_entryPoint == address(0)) revert InvalidAddress();

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

        // deploy a dedicated session key manager to shrink bytecode size
        sessionKeyManager = ISessionKeyManager(
            address(new SessionKeyManager(_verificationLogger, address(this)))
        );
        // deploy a lightweight stats manager
        statsManager = IWalletStatsManager(address(new WalletStatsManager()));
        // deploy recovery manager
        recoveryManager = IRecoveryManager(
            address(new RecoveryManager(_verificationLogger, _guardianManager))
        );
    }

    function createWallet(
        WalletType walletType,
        bytes32 salt,
        address[] memory initialSigners,
        uint256 signatureThreshold,
        uint256 trustScoreThreshold,
        uint256 dailySpendingLimit
    ) external payable nonReentrant returns (address) {
        if (msg.value < creationFee) revert FeeTooLow();
        if (salt == bytes32(0)) revert InvalidParam();
        if (ownerToWallet[msg.sender] != address(0)) revert InvalidParam();
        if (saltToWallet[salt] != address(0)) revert InvalidParam();

        if (walletType == WalletType.MultiSig) {
            if (initialSigners.length < 2) revert InvalidParam();
            if (
                signatureThreshold == 0 ||
                signatureThreshold > initialSigners.length
            ) revert InvalidParam();
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

        // Stats managed externally by WalletStatsManager

        verificationLogger.logEvent(
            "AAWC",
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
        if (
            !(wallet.owner == msg.sender ||
                hasRole(WALLET_ADMIN_ROLE, msg.sender))
        ) revert NotOwnerOrAdmin();
        if (wallet.isDeployed) revert AlreadyDeployed();

        bytes memory bytecode = abi.encodePacked(
            walletImplementation,
            abi.encode(wallet.owner, wallet.signers, wallet.signatureThreshold)
        );

        address deployed = Create2.deploy(0, wallet.salt, bytecode);
        if (deployed != walletAddress) revert Mismatch();

        wallet.isDeployed = true;

        verificationLogger.logEvent(
            "AAWD",
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
        if (wallet.walletAddress != userOp.sender) revert InvalidParam();
        if (wallet.status != WalletStatus.Active) revert InactiveWallet();

        // Validate nonce
        if (userOp.nonce != wallet.nonce) revert InvalidParam();
        wallet.nonce++;

        // Check trust score if required
        if (wallet.trustScoreThreshold > 0) {
            uint256 currentTrustScore = trustScore.getTrustScore(wallet.owner);
            if (currentTrustScore < wallet.trustScoreThreshold)
                revert LowTrust();
        }

        // Check daily spending limit
        _checkDailyLimit(userOp.sender, _estimateValue(userOp));

        // Execute the operation
        bool success = _executeOperation(userOp);

        // Update statistics via external manager
        statsManager.recordUserOp(
            userOp.sender,
            success,
            userOp.callGasLimit +
                userOp.verificationGasLimit +
                userOp.preVerificationGas,
            0
        );

        wallet.lastUsed = block.timestamp;

        verificationLogger.logEvent(
            "UOE",
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
        if (walletConfig.walletAddress != wallet) revert InvalidParam();
        if (walletConfig.walletType != WalletType.Guardian)
            revert InvalidParam();

        // Check if sender is a guardian
        if (!guardianManager.isGuardian(walletConfig.owner, msg.sender))
            revert NotGuardian();

        uint256 id = recoveryManager.requestRecovery(
            wallet,
            newOwner,
            reason,
            recoveryDelay,
            walletConfig.owner,
            msg.sender
        );
        walletConfig.status = WalletStatus.Recovering;
        emit RecoveryRequested(id, wallet, newOwner);
        emit WalletStatusChanged(
            wallet,
            WalletStatus.Active,
            WalletStatus.Recovering
        );
        return id;
    }

    function confirmRecovery(uint256 recoveryId, address wallet) external {
        WalletConfig storage walletConfig = wallets[wallet];
        recoveryManager.confirmRecovery(
            recoveryId,
            wallet,
            walletConfig.owner,
            msg.sender
        );
        emit RecoveryConfirmed(recoveryId, msg.sender);
    }

    function executeRecovery(
        uint256 recoveryId,
        address wallet
    ) external nonReentrant {
        WalletConfig storage walletConfig = wallets[wallet];
        address oldOwner = walletConfig.owner;
        address newOwner = recoveryManager.executeRecovery(
            recoveryId,
            wallet,
            walletConfig.owner
        );
        walletConfig.owner = newOwner;
        walletConfig.status = WalletStatus.Active;

        // Update mappings
        delete ownerToWallet[oldOwner];
        ownerToWallet[newOwner] = wallet;

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
        if (walletConfig.owner != msg.sender) revert NotOwnerOrAdmin();
        sessionKeyManager.addSessionKey(
            wallet,
            sessionKey,
            validUntil,
            spendingLimit,
            allowedFunctions,
            allowedContracts
        );
    }

    function revokeSessionKey(address wallet, address sessionKey) external {
        WalletConfig storage walletConfig = wallets[wallet];
        if (walletConfig.owner != msg.sender) revert NotOwnerOrAdmin();
        sessionKeyManager.revokeSessionKey(wallet, sessionKey);
    }

    function updateWalletSettings(
        address wallet,
        uint256 newDailyLimit,
        uint256 newTrustThreshold
    ) external {
        WalletConfig storage walletConfig = wallets[wallet];
        if (walletConfig.owner != msg.sender) revert NotOwnerOrAdmin();

        walletConfig.dailySpendingLimit = newDailyLimit;
        walletConfig.trustScoreThreshold = newTrustThreshold;

        verificationLogger.logEvent(
            "WSU",
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
        if (walletConfig.owner != msg.sender) revert NotOwnerOrAdmin();
        if (walletConfig.walletType != WalletType.MultiSig)
            revert InvalidParam();
        if (newSigners.length < 2) revert InvalidParam();
        if (newThreshold == 0 || newThreshold > newSigners.length)
            revert InvalidParam();

        walletConfig.signers = newSigners;
        walletConfig.signatureThreshold = newThreshold;

        verificationLogger.logEvent(
            "SUN",
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
    ) external view returns (IWalletStatsManager.UserOpStats memory) {
        return statsManager.getStats(wallet);
    }

    function getSessionKeys(
        address wallet
    ) external view returns (address[] memory) {
        return sessionKeyManager.getSessionKeys(wallet);
    }

    function isSessionKeyValid(
        address wallet,
        address sessionKey
    ) external view returns (bool) {
        return sessionKeyManager.isSessionKeyValid(wallet, sessionKey);
    }

    function getRecoveries(address wallet) external view returns (uint256) {
        return recoveryManager.getRecoveriesCount(wallet);
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
        if (userOp.callGasLimit < 21000) revert LowGas();
        if (userOp.verificationGasLimit < 100000) revert LowGas();
        if (userOp.preVerificationGas < 21000) revert LowGas();

        // Validate gas prices are within reasonable bounds
        if (userOp.maxFeePerGas < userOp.maxPriorityFeePerGas)
            revert GasPricing();
        if (userOp.maxFeePerGas > 1000 gwei) revert GasPriceTooHigh();

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

        if (walletConfig.spentToday + value > walletConfig.dailySpendingLimit)
            revert InvalidParam();

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
        if (recipient == address(0)) revert InvalidRecipient();
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoFees();

        (bool success, ) = recipient.call{value: balance}("");
        if (!success) revert WithdrawalFailed();
    }

    receive() external payable {}
}

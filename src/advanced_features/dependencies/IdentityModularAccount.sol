// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../../interfaces/IEntryPoint.sol";
import "../../interfaces/IVerificationLogger.sol";

/**
 * @title IdentityModularAccount
 * @notice Modular smart account with session keys for privacy and dApp-specific interactions
 * @dev Supports ERC-4337, session keys, subscriptions, and privacy-preserving dApp interactions
 */
contract IdentityModularAccount is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant SESSION_KEY_ROLE = keccak256("SESSION_KEY_ROLE");
    bytes32 public constant SUBSCRIPTION_ROLE = keccak256("SUBSCRIPTION_ROLE");

    // Core account settings
    address public immutable entryPoint;
    IVerificationLogger public verificationLogger;
    address public masterOwner;
    uint256 public nonce;

    // Session Key Management
    struct SessionKey {
        address keyAddress; // Session key address
        uint256 validUntil; // Expiry timestamp
        uint256 gasLimit; // Max gas per transaction
        uint256 dailyLimit; // Max value per day (wei)
        bytes32 dAppHash; // Hash of allowed dApp domain
        string dAppDomain; // Human-readable dApp domain
        bool isActive; // Key is active
        uint256 totalUsed; // Total value used by this key
        uint256 dailyUsed; // Daily value used
        uint256 lastResetDay; // Last daily reset
        string[] allowedFunctions; // Allowed function selectors
    }

    // Subscription Management
    struct Subscription {
        address provider; // Service provider
        uint256 amount; // Subscription amount
        uint256 interval; // Payment interval (seconds)
        uint256 lastPayment; // Last payment timestamp
        uint256 nextPayment; // Next payment due
        bool isActive; // Subscription is active
        string serviceName; // Human readable service name
        bytes32 planHash; // Hash of subscription plan details
        uint256 totalPaid; // Total amount paid
        uint256 paymentsCount; // Number of payments made
    }

    // Privacy Features
    struct DAppProfile {
        bytes32 profileHash; // Hash of dApp-specific data
        address sessionKey; // Dedicated session key for this dApp
        uint256 interactionCount; // Number of interactions
        bool privacyMode; // Enhanced privacy mode
        mapping(string => bytes32) encryptedData; // Encrypted user data
    }

    // State mappings
    mapping(address => SessionKey) public sessionKeys;
    mapping(bytes32 => Subscription) public subscriptions;
    mapping(string => DAppProfile) public dAppProfiles;
    mapping(uint256 => bool) public usedNonces;

    // Arrays for iteration
    address[] public sessionKeysList;
    bytes32[] public subscriptionsList;
    string[] public dAppDomainsList;

    // Events
    event SessionKeyAdded(
        address indexed sessionKey,
        string indexed dAppDomain,
        uint256 validUntil,
        uint256 gasLimit
    );
    event SessionKeyUsed(
        address indexed sessionKey,
        string indexed dAppDomain,
        uint256 gasUsed,
        bytes4 functionSelector
    );
    event SessionKeyRevoked(address indexed sessionKey, string reason);

    event SubscriptionCreated(
        bytes32 indexed subscriptionId,
        address indexed provider,
        uint256 amount,
        uint256 interval
    );
    event SubscriptionPayment(
        bytes32 indexed subscriptionId,
        uint256 amount,
        uint256 timestamp
    );
    event SubscriptionCanceled(bytes32 indexed subscriptionId, string reason);

    event DAppProfileCreated(string indexed domain, address sessionKey);
    event PrivacyModeToggled(string indexed domain, bool enabled);

    modifier onlyValidSessionKey(string memory dAppDomain) {
        DAppProfile storage profile = dAppProfiles[dAppDomain];
        require(profile.sessionKey != address(0), "No session key for dApp");

        SessionKey storage sessionKey = sessionKeys[profile.sessionKey];
        require(sessionKey.isActive, "Session key not active");
        require(
            block.timestamp <= sessionKey.validUntil,
            "Session key expired"
        );
        require(
            keccak256(abi.encodePacked(dAppDomain)) == sessionKey.dAppHash,
            "Domain mismatch"
        );
        _;
    }

    constructor(
        address _entryPoint,
        address _masterOwner,
        address _verificationLogger
    ) {
        require(_entryPoint != address(0), "Invalid EntryPoint");
        require(_masterOwner != address(0), "Invalid master owner");
        require(
            _verificationLogger != address(0),
            "Invalid verification logger"
        );

        entryPoint = _entryPoint;
        masterOwner = _masterOwner;
        verificationLogger = IVerificationLogger(_verificationLogger);

        _grantRole(DEFAULT_ADMIN_ROLE, _masterOwner);
        _grantRole(OWNER_ROLE, _masterOwner);
    }

    /**
     * @dev Create a new session key for a specific dApp
     */
    function createSessionKey(
        string memory dAppDomain,
        uint256 validFor, // Duration in seconds
        uint256 gasLimit, // Max gas per transaction
        uint256 dailyLimit, // Max value per day
        string[] memory allowedFunctions,
        bool privacyMode
    ) external onlyRole(OWNER_ROLE) returns (address sessionKeyAddress) {
        require(bytes(dAppDomain).length > 0, "Invalid dApp domain");

        // Generate deterministic session key address
        bytes32 salt = keccak256(abi.encodePacked(dAppDomain, block.timestamp));
        sessionKeyAddress = address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(address(this), salt, dAppDomain))
                )
            )
        );

        // Create session key
        SessionKey storage sessionKey = sessionKeys[sessionKeyAddress];
        sessionKey.keyAddress = sessionKeyAddress;
        sessionKey.validUntil = block.timestamp + validFor;
        sessionKey.gasLimit = gasLimit;
        sessionKey.dailyLimit = dailyLimit;
        sessionKey.dAppHash = keccak256(abi.encodePacked(dAppDomain));
        sessionKey.dAppDomain = dAppDomain;
        sessionKey.isActive = true;
        sessionKey.allowedFunctions = allowedFunctions;
        sessionKey.lastResetDay = block.timestamp / 1 days;

        // Create dApp profile
        DAppProfile storage profile = dAppProfiles[dAppDomain];
        profile.profileHash = keccak256(
            abi.encodePacked(dAppDomain, sessionKeyAddress)
        );
        profile.sessionKey = sessionKeyAddress;
        profile.privacyMode = privacyMode;

        // Add to arrays
        sessionKeysList.push(sessionKeyAddress);
        dAppDomainsList.push(dAppDomain);

        // Grant role to session key
        _grantRole(SESSION_KEY_ROLE, sessionKeyAddress);

        // Log event
        verificationLogger.logEvent(
            "SESSION_KEY_CREATED",
            address(this),
            keccak256(abi.encodePacked(dAppDomain, sessionKeyAddress))
        );

        emit SessionKeyAdded(
            sessionKeyAddress,
            dAppDomain,
            sessionKey.validUntil,
            gasLimit
        );
        emit DAppProfileCreated(dAppDomain, sessionKeyAddress);

        return sessionKeyAddress;
    }

    /**
     * @dev Execute a transaction using a session key
     */
    function executeWithSessionKey(
        string memory dAppDomain,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signature
    )
        external
        nonReentrant
        onlyValidSessionKey(dAppDomain)
        returns (bytes memory result)
    {
        // Load once to reduce stack vars
        DAppProfile storage profile = dAppProfiles[dAppDomain];
        SessionKey storage sessionKey = sessionKeys[profile.sessionKey];

        _verifySessionKeySig(sessionKey.keyAddress, to, value, data, signature);
        _checkSessionKeyLimits(sessionKey, value, data);
        _updateSessionKeyUsage(sessionKey, value);
        nonce++;

        result = _performSessionCall(to, value, data);
        profile.interactionCount++;

        _emitSessionUsage(sessionKey.keyAddress, dAppDomain, to, value, data);
        return result;
    }

    function _verifySessionKeySig(
        address expected,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signature
    ) internal view {
        bytes32 hash = keccak256(abi.encodePacked(to, value, data, nonce));
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        address recovered = ethSignedHash.recover(signature);
        require(recovered == expected, "Invalid signature");
    }

    function _performSessionCall(
        address to,
        uint256 value,
        bytes memory data
    ) internal returns (bytes memory result) {
        (bool success, bytes memory ret) = to.call{value: value}(data);
        require(success, "Transaction failed");
        return ret;
    }

    function _emitSessionUsage(
        address keyAddress,
        string memory dAppDomain,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        verificationLogger.logEvent(
            "SESSION_KEY_USED",
            address(this),
            keccak256(abi.encodePacked(dAppDomain, to, value))
        );
        emit SessionKeyUsed(keyAddress, dAppDomain, gasleft(), bytes4(data));
    }

    /**
     * @dev Create a subscription for recurring payments
     */
    function createSubscription(
        address provider,
        uint256 amount,
        uint256 interval,
        string memory serviceName,
        bytes memory planDetails
    ) external onlyRole(OWNER_ROLE) returns (bytes32 subscriptionId) {
        require(provider != address(0), "Invalid provider");
        require(amount > 0, "Invalid amount");
        require(interval > 0, "Invalid interval");

        subscriptionId = keccak256(
            abi.encodePacked(provider, serviceName, block.timestamp, nonce)
        );

        Subscription storage subscription = subscriptions[subscriptionId];
        subscription.provider = provider;
        subscription.amount = amount;
        subscription.interval = interval;
        subscription.lastPayment = block.timestamp;
        subscription.nextPayment = block.timestamp + interval;
        subscription.isActive = true;
        subscription.serviceName = serviceName;
        subscription.planHash = keccak256(planDetails);

        subscriptionsList.push(subscriptionId);
        nonce++;

        emit SubscriptionCreated(subscriptionId, provider, amount, interval);

        return subscriptionId;
    }

    /**
     * @dev Execute subscription payment
     */
    function executeSubscriptionPayment(
        bytes32 subscriptionId
    ) external nonReentrant returns (bool success) {
        Subscription storage subscription = subscriptions[subscriptionId];
        require(subscription.isActive, "Subscription not active");
        require(
            block.timestamp >= subscription.nextPayment,
            "Payment not due yet"
        );
        require(
            address(this).balance >= subscription.amount,
            "Insufficient balance"
        );

        // Execute payment
        (success, ) = subscription.provider.call{value: subscription.amount}(
            ""
        );
        require(success, "Payment failed");

        // Update subscription
        subscription.lastPayment = block.timestamp;
        subscription.nextPayment = block.timestamp + subscription.interval;
        subscription.totalPaid += subscription.amount;
        subscription.paymentsCount++;

        emit SubscriptionPayment(
            subscriptionId,
            subscription.amount,
            block.timestamp
        );

        return true;
    }

    function _checkSessionKeyLimits(
        SessionKey storage sessionKey,
        uint256 value,
        bytes memory data
    ) internal view {
        // Check function is allowed
        if (sessionKey.allowedFunctions.length > 0) {
            bytes4 selector = bytes4(data);
            bool isAllowed = false;
            for (uint256 i = 0; i < sessionKey.allowedFunctions.length; i++) {
                if (
                    keccak256(bytes(sessionKey.allowedFunctions[i])) ==
                    keccak256(abi.encodePacked(selector))
                ) {
                    isAllowed = true;
                    break;
                }
            }
            require(isAllowed, "Function not allowed");
        }

        // Check daily limit
        uint256 currentDay = block.timestamp / 1 days;
        uint256 dailyUsed = (sessionKey.lastResetDay == currentDay)
            ? sessionKey.dailyUsed
            : 0;

        require(
            dailyUsed + value <= sessionKey.dailyLimit,
            "Daily limit exceeded"
        );
    }

    function _updateSessionKeyUsage(
        SessionKey storage sessionKey,
        uint256 value
    ) internal {
        uint256 currentDay = block.timestamp / 1 days;

        // Reset daily usage if new day
        if (sessionKey.lastResetDay < currentDay) {
            sessionKey.dailyUsed = 0;
            sessionKey.lastResetDay = currentDay;
        }

        sessionKey.dailyUsed += value;
        sessionKey.totalUsed += value;
    }

    // View functions
    function getSessionKeyInfo(
        address sessionKeyAddress
    )
        external
        view
        returns (
            uint256 validUntil,
            uint256 gasLimit,
            uint256 dailyLimit,
            string memory dAppDomain,
            bool isActive,
            uint256 dailyUsed,
            uint256 totalUsed
        )
    {
        SessionKey storage sessionKey = sessionKeys[sessionKeyAddress];
        return (
            sessionKey.validUntil,
            sessionKey.gasLimit,
            sessionKey.dailyLimit,
            sessionKey.dAppDomain,
            sessionKey.isActive,
            sessionKey.dailyUsed,
            sessionKey.totalUsed
        );
    }

    function getDAppProfile(
        string memory domain
    )
        external
        view
        returns (
            bytes32 profileHash,
            address sessionKey,
            uint256 interactionCount,
            bool privacyMode
        )
    {
        DAppProfile storage profile = dAppProfiles[domain];
        return (
            profile.profileHash,
            profile.sessionKey,
            profile.interactionCount,
            profile.privacyMode
        );
    }

    function getSubscriptionInfo(
        bytes32 subscriptionId
    )
        external
        view
        returns (
            address provider,
            uint256 amount,
            uint256 interval,
            uint256 nextPayment,
            bool isActive,
            string memory serviceName,
            uint256 totalPaid,
            uint256 paymentsCount
        )
    {
        Subscription storage subscription = subscriptions[subscriptionId];
        return (
            subscription.provider,
            subscription.amount,
            subscription.interval,
            subscription.nextPayment,
            subscription.isActive,
            subscription.serviceName,
            subscription.totalPaid,
            subscription.paymentsCount
        );
    }

    // Admin functions
    function revokeSessionKey(
        address sessionKeyAddress,
        string memory reason
    ) external onlyRole(OWNER_ROLE) {
        sessionKeys[sessionKeyAddress].isActive = false;
        _revokeRole(SESSION_KEY_ROLE, sessionKeyAddress);

        emit SessionKeyRevoked(sessionKeyAddress, reason);
    }

    function cancelSubscription(
        bytes32 subscriptionId,
        string memory reason
    ) external onlyRole(OWNER_ROLE) {
        subscriptions[subscriptionId].isActive = false;

        emit SubscriptionCanceled(subscriptionId, reason);
    }

    function togglePrivacyMode(
        string memory domain,
        bool enabled
    ) external onlyRole(OWNER_ROLE) {
        dAppProfiles[domain].privacyMode = enabled;

        emit PrivacyModeToggled(domain, enabled);
    }

    // ERC-4337 compatibility
    function validateUserOp(
        IEntryPoint.UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // Only entry point can call this
        require(msg.sender == entryPoint, "Only EntryPoint");

        // Validate signature against master owner or session key
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address recovered = hash.recover(userOp.signature);

        if (recovered == masterOwner || hasRole(SESSION_KEY_ROLE, recovered)) {
            // Pay prefund if needed
            if (missingAccountFunds > 0) {
                (bool success, ) = payable(msg.sender).call{
                    value: missingAccountFunds
                }("");
                require(success, "Failed to pay prefund");
            }
            return 0; // Valid
        }

        return 1; // Invalid
    }

    // Emergency functions
    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        payable(masterOwner).transfer(address(this).balance);
    }

    // Receive ETH
    receive() external payable {}

    fallback() external payable {}
}

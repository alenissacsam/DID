// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./BaseAccountModule.sol";
import {IVerificationLogger} from "../../interfaces/IVerificationLogger.sol";

/**
 * @title SubscriptionModule
 * @notice Handles recurring payment logic for the identity modular account.
 * @dev Adds overdue detection, auto-cancel after grace, failure tracking, and custom errors.
 */
contract SubscriptionModule is BaseAccountModule {
    struct Subscription {
        address provider; // Payment recipient
        uint256 amount; // Payment amount in wei
        uint256 interval; // Interval between payments (seconds)
        uint256 lastPayment; // Timestamp of last successful payment
        uint256 nextPayment; // Scheduled next payment timestamp
        bool isActive; // Subscription active flag
        string serviceName; // Human-readable service name
        bytes32 planHash; // Hash of plan details blob
        uint256 totalPaid; // Cumulative wei paid
        uint256 paymentsCount; // Number of successful payments
        uint256 failedAttempts; // Number of failed payment attempts since last success
        uint256 graceEndsAt; // End of grace period after a missed payment
    }

    // Storage
    mapping(bytes32 => Subscription) public subscriptions;
    bytes32[] public subscriptionsList;

    // Config
    uint256 public constant MAX_INTERVAL = 365 days;
    uint256 public constant MIN_INTERVAL = 1 hours;
    uint256 public constant DEFAULT_GRACE_PERIOD = 3 days;
    uint256 public constant MAX_GRACE_PERIOD = 30 days;

    // Errors
    error ErrorBadProvider();
    error ErrorBadAmount();
    error ErrorBadInterval();
    error ErrorSubExists();
    error ErrorSubInactive();
    error ErrorNotDue(uint256 nextPayment, uint256 nowTs);
    error ErrorNoSuchSubscription();
    error ErrorAlreadyInactive();

    // Events
    event SubscriptionCreated(
        bytes32 indexed id,
        address indexed provider,
        uint256 amount,
        uint256 interval,
        uint256 nextPayment
    );
    event SubscriptionPayment(
        bytes32 indexed id,
        uint256 amount,
        uint256 timestamp,
        uint256 nextPayment
    );
    event SubscriptionCanceled(
        bytes32 indexed id,
        string reason,
        bool autoCancel
    );
    event SubscriptionOverdue(bytes32 indexed id, uint256 graceEndsAt);
    event SubscriptionPaymentFailed(bytes32 indexed id, uint256 attemptTs);

    // Logger (optional)
    IVerificationLogger public logger;

    constructor(address _account) BaseAccountModule(_account) {}

    function setLogger(address _logger) external onlyAccount {
        logger = IVerificationLogger(_logger);
    }

    function moduleId() external pure returns (bytes32) {
        return keccak256("SUBSCRIPTION_MODULE_V1");
    }

    /**
     * @notice Create a new subscription
     * @param provider Recipient of recurring payments
     * @param amount Payment amount in wei
     * @param interval Interval between payments (seconds)
     * @param serviceName Label
     * @param planDetails Opaque details blob
     * @param nonce Account-provided nonce for uniqueness
     */
    function createSubscription(
        address provider,
        uint256 amount,
        uint256 interval,
        string memory serviceName,
        bytes memory planDetails,
        uint256 nonce
    ) external onlyAccount returns (bytes32 id) {
        if (provider == address(0)) revert ErrorBadProvider();
        if (amount == 0) revert ErrorBadAmount();
        if (interval < MIN_INTERVAL || interval > MAX_INTERVAL)
            revert ErrorBadInterval();

        id = keccak256(
            abi.encodePacked(provider, serviceName, block.timestamp, nonce)
        );
        if (subscriptions[id].provider != address(0)) revert ErrorSubExists();

        Subscription storage s = subscriptions[id];
        uint256 firstNext = block.timestamp + interval;
        s.provider = provider;
        s.amount = amount;
        s.interval = interval;
        s.lastPayment = block.timestamp;
        s.nextPayment = firstNext;
        s.isActive = true;
        s.serviceName = serviceName;
        s.planHash = keccak256(planDetails);
        s.graceEndsAt = 0; // not overdue yet
        subscriptionsList.push(id);

        emit SubscriptionCreated(id, provider, amount, interval, firstNext);
        _log("SUB_CREATED", abi.encode(id, provider, amount, interval));
    }

    /**
     * @notice Execute a due subscription payment.
     * @dev Auto-cancels if grace period passed.
     */
    function executePayment(
        bytes32 id
    ) external payable onlyAccount returns (bool) {
        Subscription storage s = subscriptions[id];
        if (s.provider == address(0)) revert ErrorNoSuchSubscription();
        if (!s.isActive) revert ErrorSubInactive();

        uint256 nowTs = block.timestamp;
        if (nowTs < s.nextPayment) revert ErrorNotDue(s.nextPayment, nowTs);

        // If already overdue and grace expired -> auto-cancel
        if (s.graceEndsAt != 0 && nowTs > s.graceEndsAt) {
            s.isActive = false;
            emit SubscriptionCanceled(id, "GRACE_EXPIRED", true);
            _log("SUB_AUTO_CANCEL", abi.encode(id, s.provider));
            return false; // auto-cancelled
        }

        (bool success, ) = s.provider.call{value: s.amount}("");
        if (!success) {
            s.failedAttempts++;
            if (s.graceEndsAt == 0) {
                uint256 grace = _boundedGrace(DEFAULT_GRACE_PERIOD);
                s.graceEndsAt = nowTs + grace;
                emit SubscriptionOverdue(id, s.graceEndsAt);
                _log("SUB_OVERDUE", abi.encode(id, s.graceEndsAt));
            }
            emit SubscriptionPaymentFailed(id, nowTs);
            _log("SUB_PAY_FAIL", abi.encode(id, nowTs));
            return false;
        }

        // Success path
        s.failedAttempts = 0;
        s.graceEndsAt = 0; // clear grace
        s.lastPayment = nowTs;
        uint256 newNext = nowTs + s.interval;
        s.nextPayment = newNext;
        s.totalPaid += s.amount;
        s.paymentsCount++;

        emit SubscriptionPayment(id, s.amount, nowTs, newNext);
        _log("SUB_PAY_OK", abi.encode(id, s.amount, newNext));
        return true;
    }

    /**
     * @notice Cancel a subscription manually.
     */
    function cancel(bytes32 id, string memory reason) external onlyAccount {
        Subscription storage s = subscriptions[id];
        if (s.provider == address(0)) revert ErrorNoSuchSubscription();
        if (!s.isActive) revert ErrorAlreadyInactive();
        s.isActive = false;
        emit SubscriptionCanceled(id, reason, false);
        _log("SUB_CANCEL", abi.encode(id, reason));
    }

    function get(bytes32 id) external view returns (Subscription memory) {
        return subscriptions[id];
    }

    function listIds() external view returns (bytes32[] memory) {
        return subscriptionsList;
    }

    function isOverdue(
        bytes32 id
    ) external view returns (bool overdue, uint256 graceEndsAt) {
        Subscription storage s = subscriptions[id];
        if (s.provider == address(0) || !s.isActive) return (false, 0);
        if (block.timestamp >= s.nextPayment) {
            if (s.graceEndsAt == 0) return (false, 0); // not yet marked as overdue by a failed attempt
            return (true, s.graceEndsAt);
        }
        return (false, 0);
    }

    // Status helper
    enum Status {
        None,
        Active,
        InGrace,
        AutoCanceled,
        Canceled
    }

    function getStatus(
        bytes32 id
    )
        external
        view
        returns (
            Status status,
            uint256 graceEndsAt,
            uint256 nextPayment,
            bool due
        )
    {
        Subscription storage s = subscriptions[id];
        if (s.provider == address(0)) return (Status.None, 0, 0, false);
        if (!s.isActive) {
            // Distinguish manual vs auto-cancel by grace window past
            if (s.graceEndsAt != 0 && block.timestamp > s.graceEndsAt) {
                return (
                    Status.AutoCanceled,
                    s.graceEndsAt,
                    s.nextPayment,
                    false
                );
            }
            return (Status.Canceled, s.graceEndsAt, s.nextPayment, false);
        }
        bool isDue = block.timestamp >= s.nextPayment;
        if (s.graceEndsAt != 0) {
            return (Status.InGrace, s.graceEndsAt, s.nextPayment, isDue);
        }
        return (Status.Active, 0, s.nextPayment, isDue);
    }

    function _boundedGrace(uint256 proposed) private pure returns (uint256) {
        if (proposed > MAX_GRACE_PERIOD) return MAX_GRACE_PERIOD;
        return proposed;
    }

    function _log(string memory tag, bytes memory data) internal {
        if (address(logger) != address(0)) {
            // best-effort: hash payload for storage efficiency in logger
            bytes32 h = keccak256(data);
            try logger.logEvent(tag, address(this), h) {} catch {}
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./EduCertAccountDeployer.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";

/**
 * @title EduCertAccountFactory
 * @notice Factory for creating EduCert modular accounts with Alchemy Account Kit integration
 * @dev Supports gasless account creation, session key setup, and Alchemy paymaster integration
 */
contract EduCertAccountFactory is AccessControl {
    // Compact errors to reduce bytecode
    error InvalidAddress();
    error InvalidOwner();
    error MaxAccountsExceeded();
    error AccountExists();
    error InvalidIndex();
    error CannotProcess();

    // Core contracts
    address public immutable entryPoint;
    IVerificationLogger public immutable verificationLogger;
    ITrustScore public immutable trustScore;

    // Compact configuration
    struct Config {
        uint256 initialTrustScore; // Initial trust score for new users
        uint256 maxAccountsPerUser; // Max accounts per user
        bool restricted; // If true, only bundler/authorized creators can create
    }

    Config public config;
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");
    address public bundler; // Alchemy bundler or any trusted relayer
    IEduCertAccountDeployer public deployer;

    // State tracking
    mapping(address => address[]) public userAccounts; // owner => account addresses

    // Events
    event AccountCreated(
        address indexed account,
        address indexed owner,
        bytes32 salt,
        bool gasless,
        uint256 trustScore
    );
    event ConfigUpdated(
        uint256 initialTrustScore,
        uint256 maxAccountsPerUser,
        bool restricted
    );
    event BundlerUpdated(address bundler);
    event CreatorAuthUpdated(address creator, bool allowed);

    constructor(
        address _entryPoint,
        address _verificationLogger,
        address _trustScore,
        uint256 _maxAccountsPerUser
    ) {
        if (
            _entryPoint == address(0) ||
            _verificationLogger == address(0) ||
            _trustScore == address(0)
        ) {
            revert InvalidAddress();
        }

        entryPoint = _entryPoint;
        verificationLogger = IVerificationLogger(_verificationLogger);
        trustScore = ITrustScore(_trustScore);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        // Set up config
        config = Config({
            initialTrustScore: 25, // Starting trust score
            maxAccountsPerUser: _maxAccountsPerUser,
            restricted: true
        });
        deployer = new EduCertAccountDeployer();
    }

    /**
     * @dev Create a new EduCert modular account
     * @param owner The owner of the account
     * @param salt Salt for deterministic address generation
     * @return account The created account address
     */
    function createAccount(
        address owner,
        bytes32 salt,
        bool /*setupSessionKeys*/
    ) external returns (address account) {
        if (owner == address(0)) revert InvalidOwner();

        // If restricted, only bundler or authorized creators may create
        if (config.restricted) {
            if (!(msg.sender == bundler || hasRole(CREATOR_ROLE, msg.sender)))
                revert CannotProcess();
        }

        // Check account limit per user
        if (userAccounts[owner].length >= config.maxAccountsPerUser)
            revert MaxAccountsExceeded();

        // Generate deterministic address
        bytes32 finalSalt = keccak256(
            abi.encodePacked(owner, salt, block.timestamp)
        );

        // Deploy account via external deployer (shrinks factory bytecode)
        account = deployer.deploy(
            entryPoint,
            owner,
            address(verificationLogger),
            finalSalt
        );

        // Update mappings
        userAccounts[owner].push(account);

        // Initialize trust score: initialize then add initial delta
        try trustScore.initializeUser(account) {
            if (config.initialTrustScore > 0) {
                try
                    trustScore.updateScore(
                        account,
                        int256(uint256(config.initialTrustScore)),
                        "Factory init"
                    )
                {} catch {}
            }
        } catch {
            // If already initialized, just add initial delta
            if (config.initialTrustScore > 0) {
                try
                    trustScore.updateScore(
                        account,
                        int256(uint256(config.initialTrustScore)),
                        "Factory init"
                    )
                {} catch {}
            }
        }

        emit AccountCreated(
            account,
            owner,
            finalSalt,
            true,
            config.initialTrustScore
        );

        return account;
    }

    function getUserAccounts(
        address owner
    ) external view returns (address[] memory) {
        return userAccounts[owner];
    }

    function updateConfig(
        uint256 initialTrustScore,
        uint256 maxAccountsPerUser,
        bool restricted
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        config.initialTrustScore = initialTrustScore;
        config.maxAccountsPerUser = maxAccountsPerUser;
        config.restricted = restricted;
        emit ConfigUpdated(initialTrustScore, maxAccountsPerUser, restricted);
    }

    function setBundler(
        address _bundler
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bundler = _bundler;
        emit BundlerUpdated(_bundler);
    }

    // No payable flows; bundlers cover gas. No emergency withdraw needed.
}

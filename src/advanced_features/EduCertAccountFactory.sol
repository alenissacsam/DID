// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "./EduCertModularAccount.sol";
import "./AlchemyGasManager.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/ITrustScore.sol";

/**
 * @title EduCertAccountFactory
 * @notice Factory for creating EduCert modular accounts with Alchemy Account Kit integration
 * @dev Supports gasless account creation, session key setup, and Alchemy paymaster integration
 */
contract EduCertAccountFactory is AccessControl {
    bytes32 public constant FACTORY_ADMIN_ROLE =
        keccak256("FACTORY_ADMIN_ROLE");

    // Core contracts
    address public immutable entryPoint;
    IVerificationLogger public verificationLogger;
    ITrustScore public trustScore;
    AlchemyGasManager public gasManager;

    // Alchemy Account Kit integration
    struct AlchemyIntegration {
        string apiKey; // Alchemy API key (hashed for security)
        string appId; // Alchemy app identifier
        address signerAddress; // Alchemy signer service address
        bool useAlchemySigner; // Use Alchemy's signer service
        uint256 maxAccountsPerUser; // Max accounts per user
    }

    // Account creation settings
    struct AccountCreationConfig {
        uint256 creationFee; // Fee to create account (can be 0 for gasless)
        uint256 initialTrustScore; // Initial trust score for new users
        bool gaslessCreation; // Enable gasless account creation
        bool autoSetupSessionKeys; // Auto-create session keys for popular dApps
        string[] defaultDApps; // Default dApps for session keys
    }

    AlchemyIntegration public alchemyConfig;
    AccountCreationConfig public creationConfig;

    // State tracking
    mapping(address => address[]) public userAccounts; // owner => account addresses
    mapping(address => address) public accountOwners; // account => owner
    mapping(bytes32 => address) public saltToAccount; // salt => account address
    mapping(address => bool) public isEduCertAccount; // account => is valid
    mapping(address => uint256) public accountCreationTime;

    address[] public allAccounts;

    // Events
    event AccountCreated(
        address indexed account,
        address indexed owner,
        bytes32 salt,
        bool gasless,
        uint256 trustScore
    );
    event AccountUpgraded(address indexed account, address newImplementation);
    event AlchemyConfigUpdated(string appId, address signerAddress);
    event CreationConfigUpdated(uint256 fee, bool gaslessCreation);
    event SessionKeysAutoSetup(address indexed account, string[] dApps);

    constructor(
        address _entryPoint,
        address _verificationLogger,
        address _trustScore,
        address _gasManager,
        string memory _alchemyAppId,
        address _alchemySignerAddress
    ) {
        require(_entryPoint != address(0), "Invalid EntryPoint");
        require(
            _verificationLogger != address(0),
            "Invalid verification logger"
        );
        require(_trustScore != address(0), "Invalid trust score");

        entryPoint = _entryPoint;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FACTORY_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        trustScore = ITrustScore(_trustScore);
        gasManager = AlchemyGasManager(payable(_gasManager));

        // Set up Alchemy integration
        alchemyConfig = AlchemyIntegration({
            apiKey: "", // Set separately for security
            appId: _alchemyAppId,
            signerAddress: _alchemySignerAddress,
            useAlchemySigner: true,
            maxAccountsPerUser: 5
        });

        // Set up creation config
        creationConfig = AccountCreationConfig({
            creationFee: 0, // Free account creation
            initialTrustScore: 25, // Starting trust score
            gaslessCreation: true,
            autoSetupSessionKeys: true,
            defaultDApps: new string[](0)
        });

        // Add popular dApps for auto session key setup
        _setupDefaultDApps();
    }

    /**
     * @dev Create a new EduCert modular account
     * @param owner The owner of the account
     * @param salt Salt for deterministic address generation
     * @param setupSessionKeys Whether to auto-setup session keys
     * @return account The created account address
     */
    function createAccount(
        address owner,
        bytes32 salt,
        bool setupSessionKeys
    ) external payable returns (address account) {
        require(owner != address(0), "Invalid owner");

        // Check creation fee if not gasless
        if (!creationConfig.gaslessCreation) {
            require(
                msg.value >= creationConfig.creationFee,
                "Insufficient creation fee"
            );
        }

        // Check account limit per user
        require(
            userAccounts[owner].length < alchemyConfig.maxAccountsPerUser,
            "Max accounts per user exceeded"
        );

        // Generate deterministic address
        bytes32 finalSalt = keccak256(
            abi.encodePacked(owner, salt, block.timestamp)
        );

        // Check if account already exists
        require(
            saltToAccount[finalSalt] == address(0),
            "Account already exists"
        );

        // Deploy account using Create2
        account = address(
            new EduCertModularAccount{salt: finalSalt}(
                entryPoint,
                owner,
                address(verificationLogger)
            )
        );

        // Update mappings
        userAccounts[owner].push(account);
        accountOwners[account] = owner;
        saltToAccount[finalSalt] = account;
        isEduCertAccount[account] = true;
        accountCreationTime[account] = block.timestamp;
        allAccounts.push(account);

        // Initialize trust score
        trustScore.initializeUserScore(
            account,
            creationConfig.initialTrustScore
        );

        // Auto-setup session keys if enabled
        if (setupSessionKeys && creationConfig.autoSetupSessionKeys) {
            _autoSetupSessionKeys(account);
        }

        // Log creation
        verificationLogger.logEvent(
            "ACCOUNT_CREATED",
            account,
            keccak256(abi.encodePacked(owner, salt, finalSalt))
        );

        emit AccountCreated(
            account,
            owner,
            finalSalt,
            creationConfig.gaslessCreation,
            creationConfig.initialTrustScore
        );

        return account;
    }

    /**
     * @dev Create account with Alchemy Account Kit integration
     * @param owner The owner of the account
     * @param sessionKeyCount Number of session keys to generate automatically
     * @return account The created account address
     */
    function createAccountWithAlchemy(
        address owner,
        uint256 sessionKeyCount,
        bytes memory /*alchemySignature*/,
        bytes memory /*additionalData*/
    ) external returns (address account) {
        require(owner != address(0), "Invalid owner");

        // Create the account using similar logic to createAccount
        bytes32 salt = keccak256(
            abi.encodePacked(owner, block.timestamp, "alchemy")
        );

        // Check if account already exists
        require(saltToAccount[salt] == address(0), "Account already exists");

        // Deploy account using Create2
        account = address(
            new EduCertModularAccount{salt: salt}(
                entryPoint,
                owner,
                address(verificationLogger)
            )
        );

        // Update mappings
        userAccounts[owner].push(account);
        accountOwners[account] = owner;
        saltToAccount[salt] = account;
        isEduCertAccount[account] = true;
        accountCreationTime[account] = block.timestamp;
        allAccounts.push(account);

        // Initialize trust score
        trustScore.initializeUserScore(
            account,
            creationConfig.initialTrustScore
        );

        // Log creation with Alchemy integration
        verificationLogger.logEvent(
            "ACCOUNT_CREATED_WITH_ALCHEMY",
            account,
            keccak256(
                abi.encodePacked(owner, "alchemy_integration", sessionKeyCount)
            )
        );

        // Auto-setup session keys for privacy
        if (sessionKeyCount > 0 || creationConfig.autoSetupSessionKeys) {
            _autoSetupSessionKeys(account);
        }

        emit AccountCreated(
            account,
            owner,
            salt,
            true, // Gasless via Alchemy
            creationConfig.initialTrustScore
        );

        return account;
    }

    /**
     * @dev Get account address before deployment (for UI/frontend)
     */
    function getAccountAddress(
        address owner,
        bytes32 salt
    ) external view returns (address predictedAddress) {
        bytes32 finalSalt = keccak256(
            abi.encodePacked(owner, salt, block.timestamp)
        );

        bytes memory bytecode = abi.encodePacked(
            type(EduCertModularAccount).creationCode,
            abi.encode(entryPoint, owner, address(verificationLogger))
        );

        predictedAddress = Create2.computeAddress(
            finalSalt,
            keccak256(bytecode)
        );
        return predictedAddress;
    }

    function _autoSetupSessionKeys(address account) internal {
        string[] memory domains = creationConfig.defaultDApps;
        _setupCustomSessionKeys(account, domains);

        emit SessionKeysAutoSetup(account, domains);
    }

    function _setupCustomSessionKeys(
        address account,
        string[] memory domains
    ) internal {
        for (uint256 i = 0; i < domains.length; i++) {
            try
                EduCertModularAccount(payable(account)).createSessionKey(
                    domains[i],
                    30 days, // Valid for 30 days
                    500000, // 500k gas limit per transaction
                    1 ether, // 1 ETH daily limit
                    new string[](0), // Allow all functions initially
                    true // Privacy mode enabled
                )
            {
                // Session key created successfully
            } catch {
                // Ignore failures, continue with other domains
            }
        }
    }

    function _setupDefaultDApps() internal {
        // Popular dApps for auto session key creation
        creationConfig.defaultDApps.push("uniswap.org");
        creationConfig.defaultDApps.push("opensea.io");
        creationConfig.defaultDApps.push("compound.finance");
        creationConfig.defaultDApps.push("aave.com");
        creationConfig.defaultDApps.push("ens.domains");
        creationConfig.defaultDApps.push("metamask.io");
        creationConfig.defaultDApps.push("rainbow.me");
        creationConfig.defaultDApps.push("educert.app"); // Your own dApp
    }

    // View functions
    function getUserAccounts(
        address owner
    ) external view returns (address[] memory) {
        return userAccounts[owner];
    }

    function getAccountOwner(address account) external view returns (address) {
        return accountOwners[account];
    }

    function getAllAccounts() external view returns (address[] memory) {
        return allAccounts;
    }

    function getTotalAccounts() external view returns (uint256) {
        return allAccounts.length;
    }

    function getAccountsByOwner(
        address owner
    )
        external
        view
        returns (
            address[] memory accounts,
            uint256[] memory creationTimes,
            bool[] memory isValid
        )
    {
        address[] memory userAccountList = userAccounts[owner];
        uint256 length = userAccountList.length;

        accounts = new address[](length);
        creationTimes = new uint256[](length);
        isValid = new bool[](length);

        for (uint256 i = 0; i < length; i++) {
            accounts[i] = userAccountList[i];
            creationTimes[i] = accountCreationTime[userAccountList[i]];
            isValid[i] = isEduCertAccount[userAccountList[i]];
        }

        return (accounts, creationTimes, isValid);
    }

    function updateAlchemyConfig(
        string memory appId,
        address signerAddress,
        bool useAlchemySigner,
        uint256 maxAccountsPerUser
    ) external onlyRole(FACTORY_ADMIN_ROLE) {
        alchemyConfig.appId = appId;
        alchemyConfig.signerAddress = signerAddress;
        alchemyConfig.useAlchemySigner = useAlchemySigner;
        alchemyConfig.maxAccountsPerUser = maxAccountsPerUser;

        emit AlchemyConfigUpdated(appId, signerAddress);
    }

    function updateCreationConfig(
        uint256 creationFee,
        uint256 initialTrustScore,
        bool gaslessCreation,
        bool autoSetupSessionKeys
    ) external onlyRole(FACTORY_ADMIN_ROLE) {
        creationConfig.creationFee = creationFee;
        creationConfig.initialTrustScore = initialTrustScore;
        creationConfig.gaslessCreation = gaslessCreation;
        creationConfig.autoSetupSessionKeys = autoSetupSessionKeys;

        emit CreationConfigUpdated(creationFee, gaslessCreation);
    }

    function addDefaultDApp(
        string memory domain
    ) external onlyRole(FACTORY_ADMIN_ROLE) {
        creationConfig.defaultDApps.push(domain);
    }

    function removeDefaultDApp(
        uint256 index
    ) external onlyRole(FACTORY_ADMIN_ROLE) {
        require(index < creationConfig.defaultDApps.length, "Invalid index");

        // Move last element to deleted spot and reduce array length
        creationConfig.defaultDApps[index] = creationConfig.defaultDApps[
            creationConfig.defaultDApps.length - 1
        ];
        creationConfig.defaultDApps.pop();
    }

    function getDefaultDApps() external view returns (string[] memory) {
        return creationConfig.defaultDApps;
    }

    // Emergency functions
    function emergencyPause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Implement pause functionality if needed
        // For now, we can disable gasless creation
        creationConfig.gaslessCreation = false;
    }

    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        payable(msg.sender).transfer(address(this).balance);
    }

    // Receive ETH for gasless account creation
    receive() external payable {}
}

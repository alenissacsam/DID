// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../../interfaces/IVerificationLogger.sol";

interface IContractRegistry {
    function getContractAddress(
        string memory name
    ) external view returns (address);

    function registerContract(
        string memory name,
        address contractAddress,
        string memory version
    ) external;
}

// Compact Migration Manager (size-optimized)
contract MigrationManager is AccessControl, ReentrancyGuard {
    bytes32 public constant MIGRATION_ADMIN_ROLE =
        keccak256("MIGRATION_ADMIN_ROLE");

    // Errors (replace revert strings)
    error InvalidAddr();
    error EmptyName();
    error EmptyFromVer();
    error EmptyToVer();
    error NoDataTypes();
    error NoContracts();
    error InvalidRecords();
    error NotPlannedOrPaused();
    error NotAuthorized();
    error EmergPaused();
    error NotInProgress();
    error NotPaused();
    error NotRollbackable();
    error NoRollbackPlan();
    error WindowExpired();
    error EmptyBatch();
    error InvalidCount();
    error BatchTooLarge();
    error InternalOnly();
    error InvalidSize();
    error InvalidTimeout();
    error InvalidWindow();

    enum MigrationStatus {
        Planned,
        InProgress,
        Paused,
        Completed,
        Failed,
        Rollback
    }
    enum DataType {
        UserIdentities,
        Certificates,
        TrustScores,
        Organizations,
        Badges,
        Governance,
        Economics,
        CrossChain,
        All
    }

    struct Migration {
        uint256 id;
        bytes32 nameHash;
        bytes32 fromVersionHash;
        bytes32 toVersionHash;
        DataType[] dataTypes;
        address[] contractsToMigrate;
        address migrationExecutor;
        uint256 plannedAt;
        uint256 startedAt;
        uint256 completedAt;
        MigrationStatus status;
        uint256 totalRecords;
        uint256 migratedRecords;
        uint256 failedRecords;
        bool hasRollbackPlan;
        bytes rollbackData;
        bytes32 migrationHash;
    }

    struct BatchMigration {
        uint256 migrationId;
        uint256 batchNumber;
        uint256 recordCount;
        bytes32 dataHash;
        uint256 processedAt;
        bool isSuccessful;
        bytes32 errorCode; // keccak256(error) or 0x0
    }

    mapping(uint256 => Migration) internal migrations;
    mapping(uint256 => BatchMigration[]) public migrationBatches;
    mapping(address => bool) public authorizedMigrationContracts;
    // versions keyed by name hash
    mapping(bytes32 => bytes32) public contractVersions;

    uint256 public migrationCounter;
    uint256[] public activeMigrations;

    IVerificationLogger public verificationLogger;
    IContractRegistry public contractRegistry;

    uint256 public maxBatchSize;
    uint256 public migrationTimeout;
    bool public emergencyPauseEnabled;
    uint256 public rollbackWindow;

    // Abbreviated events with hashes
    event MP(uint256 indexed id, bytes32 nameHash, address ex);
    event MS(uint256 indexed id, uint256 total);
    event BM(uint256 indexed id, uint256 bn, uint256 rc);
    event MC(uint256 indexed id, uint256 done);
    event MPa(uint256 indexed id, address by);
    event MR(uint256 indexed id, address by);
    event RBE(uint256 indexed id, bytes32 reasonHash);
    event EP(address indexed admin, bytes32 reasonHash);
    event ER(address indexed admin);

    constructor(address _verificationLogger, address _contractRegistry) {
        if (_verificationLogger == address(0)) revert InvalidAddr();
        if (_contractRegistry == address(0)) revert InvalidAddr();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MIGRATION_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        contractRegistry = IContractRegistry(_contractRegistry);

        maxBatchSize = 1000;
        migrationTimeout = 24 hours;
        emergencyPauseEnabled = false;
        rollbackWindow = 7 days;
    }

    // Views
    function getMigrationInfo(
        uint256 id
    )
        external
        view
        returns (
            bytes32 nameHash,
            bytes32 fromVersionHash,
            bytes32 toVersionHash,
            address executor,
            MigrationStatus status,
            uint256 plannedAt,
            uint256 startedAt,
            uint256 completedAt,
            uint256 totalRecords,
            uint256 migratedRecords,
            uint256 failedRecords,
            bool hasRollbackPlan,
            bytes32 migrationHash
        )
    {
        Migration storage m = migrations[id];
        return (
            m.nameHash,
            m.fromVersionHash,
            m.toVersionHash,
            m.migrationExecutor,
            m.status,
            m.plannedAt,
            m.startedAt,
            m.completedAt,
            m.totalRecords,
            m.migratedRecords,
            m.failedRecords,
            m.hasRollbackPlan,
            m.migrationHash
        );
    }

    function getMigrationArrays(
        uint256 id
    )
        external
        view
        returns (
            DataType[] memory dataTypes,
            address[] memory contractsToMigrate
        )
    {
        Migration storage m = migrations[id];
        return (m.dataTypes, m.contractsToMigrate);
    }

    // Core logic
    function planMigration(
        string calldata name,
        string calldata fromVersion,
        string calldata toVersion,
        DataType[] calldata dataTypes,
        address[] calldata contractsToMigrate,
        uint256 estimatedRecords,
        bytes calldata rollbackData
    ) external onlyRole(MIGRATION_ADMIN_ROLE) returns (uint256) {
        if (bytes(name).length == 0) revert EmptyName();
        if (bytes(fromVersion).length == 0) revert EmptyFromVer();
        if (bytes(toVersion).length == 0) revert EmptyToVer();
        if (dataTypes.length == 0) revert NoDataTypes();
        if (contractsToMigrate.length == 0) revert NoContracts();
        if (estimatedRecords == 0) revert InvalidRecords();

        migrationCounter++;
        uint256 id = migrationCounter;
        bytes32 nameHash = keccak256(bytes(name));
        bytes32 fromHash = keccak256(bytes(fromVersion));
        bytes32 toHash = keccak256(bytes(toVersion));

        Migration storage m = migrations[id];
        m.id = id;
        m.nameHash = nameHash;
        m.fromVersionHash = fromHash;
        m.toVersionHash = toHash;
        for (uint256 i; i < dataTypes.length; i++)
            m.dataTypes.push(dataTypes[i]);
        for (uint256 i; i < contractsToMigrate.length; i++)
            m.contractsToMigrate.push(contractsToMigrate[i]);
        m.migrationExecutor = msg.sender;
        m.plannedAt = block.timestamp;
        m.status = MigrationStatus.Planned;
        m.totalRecords = estimatedRecords;
        m.hasRollbackPlan = rollbackData.length > 0;
        m.rollbackData = rollbackData;
        m.migrationHash = keccak256(
            abi.encodePacked(nameHash, contractsToMigrate, block.timestamp)
        );

        activeMigrations.push(id);

        verificationLogger.logEvent("MP", msg.sender, m.migrationHash);
        emit MP(id, nameHash, msg.sender);
        return id;
    }

    function startMigration(
        uint256 id
    ) external onlyRole(MIGRATION_ADMIN_ROLE) nonReentrant {
        if (emergencyPauseEnabled) revert EmergPaused();
        Migration storage m = migrations[id];
        if (
            !(m.status == MigrationStatus.Planned ||
                m.status == MigrationStatus.Paused)
        ) revert NotPlannedOrPaused();
        if (m.migrationExecutor != msg.sender) revert NotAuthorized();
        m.status = MigrationStatus.InProgress;
        m.startedAt = block.timestamp;
        verificationLogger.logEvent("MS", msg.sender, m.migrationHash);
        emit MS(id, m.totalRecords);
    }

    function executeBatchMigration(
        uint256 id,
        uint256 batchNumber,
        bytes calldata batchData,
        uint256 recordCount
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        if (batchData.length == 0) revert EmptyBatch();
        if (recordCount == 0) revert InvalidCount();
        if (recordCount > maxBatchSize) revert BatchTooLarge();
        Migration storage m = migrations[id];
        if (m.status != MigrationStatus.InProgress) revert NotInProgress();

        bytes32 hash = keccak256(batchData);
        bool success;
        bytes32 code;
        try this.processBatchData(batchData) {
            m.migratedRecords += recordCount;
            success = true;
        } catch Error(string memory err) {
            m.failedRecords += recordCount;
            success = false;
            code = keccak256(bytes(err));
        } catch {
            m.failedRecords += recordCount;
            success = false;
            code = keccak256("UnknownError");
        }

        migrationBatches[id].push(
            BatchMigration({
                migrationId: id,
                batchNumber: batchNumber,
                recordCount: recordCount,
                dataHash: hash,
                processedAt: block.timestamp,
                isSuccessful: success,
                errorCode: code
            })
        );

        verificationLogger.logEvent(success ? "BMS" : "BMF", msg.sender, hash);
        emit BM(id, batchNumber, recordCount);
    }

    function completeMigration(
        uint256 id
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        if (m.status != MigrationStatus.InProgress) revert NotInProgress();
        if (m.migrationExecutor != msg.sender) revert NotAuthorized();
        m.status = MigrationStatus.Completed;
        m.completedAt = block.timestamp;
        verificationLogger.logEvent("MC", msg.sender, m.migrationHash);
        emit MC(id, m.migratedRecords);
        _removeActiveMigration(id);
        for (uint256 i; i < m.contractsToMigrate.length; i++) {
            bytes32 nameHash = keccak256(
                bytes(_getContractName(m.contractsToMigrate[i]))
            );
            contractVersions[nameHash] = m.toVersionHash;
        }
    }

    function pauseMigration(
        uint256 id,
        string calldata reason
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        if (m.status != MigrationStatus.InProgress) revert NotInProgress();
        m.status = MigrationStatus.Paused;
        bytes32 rh = keccak256(bytes(reason));
        verificationLogger.logEvent("MPa", msg.sender, rh);
        emit MPa(id, msg.sender);
    }

    function resumeMigration(
        uint256 id
    ) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        if (m.status != MigrationStatus.Paused) revert NotPaused();
        if (emergencyPauseEnabled) revert EmergPaused();
        m.status = MigrationStatus.InProgress;
        verificationLogger.logEvent("MR", msg.sender, m.migrationHash);
        emit MR(id, msg.sender);
    }

    function rollbackMigration(
        uint256 id,
        string calldata reason
    ) external onlyRole(MIGRATION_ADMIN_ROLE) nonReentrant {
        Migration storage m = migrations[id];
        if (
            !(m.status == MigrationStatus.Completed ||
                m.status == MigrationStatus.Failed)
        ) revert NotRollbackable();
        if (!m.hasRollbackPlan) revert NoRollbackPlan();
        if (block.timestamp > m.completedAt + rollbackWindow)
            revert WindowExpired();
        m.status = MigrationStatus.Rollback;
        _executeRollback(id, m.rollbackData);
        bytes32 rh = keccak256(bytes(reason));
        verificationLogger.logEvent("RBE", msg.sender, m.migrationHash);
        emit RBE(id, rh);
    }

    function emergencyPause(
        string calldata reason
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyPauseEnabled = true;
        bytes32 rh = keccak256(bytes(reason));
        verificationLogger.logEvent("EP", msg.sender, rh);
        emit EP(msg.sender, rh);
    }

    function emergencyResume() external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyPauseEnabled = false;
        verificationLogger.logEvent("ER", msg.sender, bytes32(0));
        emit ER(msg.sender);
    }

    function processBatchData(bytes calldata data) external view {
        if (msg.sender != address(this)) revert InternalOnly();
        if (data.length == 0) revert EmptyBatch();
    }

    function _executeRollback(uint256, bytes memory) private {}

    function authorizeContract(
        address c,
        bool a
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        authorizedMigrationContracts[c] = a;
    }

    function _removeActiveMigration(uint256 id) private {
        for (uint256 i; i < activeMigrations.length; i++) {
            if (activeMigrations[i] == id) {
                activeMigrations[i] = activeMigrations[
                    activeMigrations.length - 1
                ];
                activeMigrations.pop();
                break;
            }
        }
    }

    function _getContractName(address c) private pure returns (string memory) {
        return string(abi.encodePacked("Contract_", c));
    }
}

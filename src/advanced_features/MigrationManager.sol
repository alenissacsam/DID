// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";

interface IContractRegistry {
    function getContractAddress(string memory name) external view returns (address);

    function registerContract(string memory name, address contractAddress, string memory version) external;
}

contract MigrationManager is AccessControl, ReentrancyGuard {
    bytes32 public constant MIGRATION_ADMIN_ROLE = keccak256("MIGRATION_ADMIN_ROLE");

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
        string name;
        string description;
        string fromVersion;
        string toVersion;
        // DO NOT EXPOSE arrays in a public mapping!
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
        string errorMessage;
        bytes32 migrationHash;
    }

    struct BatchMigration {
        uint256 migrationId;
        uint256 batchNumber;
        uint256 recordCount;
        bytes32 dataHash;
        uint256 processedAt;
        bool isSuccessful;
        string errorDetails;
    }

    struct DataBackup {
        string contractName;
        string dataType;
        bytes data;
        bytes32 backupHash;
        uint256 backupTime;
        string version;
        bool isRestored;
    }

    struct StateSnapshot {
        uint256 snapshotId;
        string contractName;
        bytes contractState;
        bytes32 stateHash;
        uint256 blockNumber;
        uint256 timestamp;
        bool isActive;
    }

    // Mappings with big structs must be internal, not public!
    mapping(uint256 => Migration) internal migrations;
    mapping(uint256 => BatchMigration[]) public migrationBatches;
    mapping(bytes32 => DataBackup) public dataBackups;
    mapping(uint256 => StateSnapshot) public stateSnapshots;
    mapping(address => bool) public authorizedMigrationContracts;
    mapping(string => string) public contractVersions;

    uint256 public migrationCounter;
    uint256 public snapshotCounter;
    uint256[] public activeMigrations;

    IVerificationLogger public verificationLogger;
    IContractRegistry public contractRegistry;

    uint256 public maxBatchSize;
    uint256 public migrationTimeout;
    bool public emergencyPauseEnabled;
    uint256 public rollbackWindow;

    event MigrationPlanned(uint256 indexed migrationId, string name, address executor);
    event MigrationStarted(uint256 indexed migrationId, uint256 totalRecords);
    event BatchMigrated(uint256 indexed migrationId, uint256 batchNumber, uint256 recordCount);
    event MigrationCompleted(uint256 indexed migrationId, uint256 migratedRecords);
    event MigrationPaused(uint256 indexed migrationId, address pausedBy);
    event MigrationResumed(uint256 indexed migrationId, address resumedBy);
    event DataBackedUp(string indexed contractName, string dataType, bytes32 backupHash);
    event DataRestored(string indexed contractName, bytes32 backupHash);
    event StateSnapshotEvent(uint256 indexed snapshotId, string contractName, bytes32 stateHash);
    event RollbackExecuted(uint256 indexed migrationId, string reason);
    event EmergencyPause(address indexed admin, string reason);
    event EmergencyResume(address indexed admin);

    constructor(address _verificationLogger, address _contractRegistry) {
        require(_verificationLogger != address(0), "Invalid verification logger");
        require(_contractRegistry != address(0), "Invalid contract registry");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MIGRATION_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        contractRegistry = IContractRegistry(_contractRegistry);

        maxBatchSize = 1000;
        migrationTimeout = 24 hours;
        emergencyPauseEnabled = false;
        rollbackWindow = 7 days;
    }

    // --- Explicit Fieldwise Getters for Migration struct ---
    function getMigrationInfo(uint256 id)
        external
        view
        returns (
            string memory name,
            string memory description,
            string memory fromVersion,
            string memory toVersion,
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
        name = m.name;
        description = m.description;
        fromVersion = m.fromVersion;
        toVersion = m.toVersion;
        executor = m.migrationExecutor;
        status = m.status;
        plannedAt = m.plannedAt;
        startedAt = m.startedAt;
        completedAt = m.completedAt;
        totalRecords = m.totalRecords;
        migratedRecords = m.migratedRecords;
        failedRecords = m.failedRecords;
        hasRollbackPlan = m.hasRollbackPlan;
        migrationHash = m.migrationHash;
    }

    function getMigrationArrays(uint256 id)
        external
        view
        returns (DataType[] memory dataTypes, address[] memory contractsToMigrate)
    {
        Migration storage m = migrations[id];
        dataTypes = m.dataTypes;
        contractsToMigrate = m.contractsToMigrate;
    }

    function getMigrationErrors(uint256 id)
        external
        view
        returns (string memory errorMessage, bytes memory rollbackData)
    {
        Migration storage m = migrations[id];
        errorMessage = m.errorMessage;
        rollbackData = m.rollbackData;
    }

    // -------------------------------------------------------

    // --- Migration logic, using fieldwise assignments only ---
    function planMigration(
        string memory name,
        string memory description,
        string memory fromVersion,
        string memory toVersion,
        DataType[] memory dataTypes,
        address[] memory contractsToMigrate,
        uint256 estimatedRecords,
        bytes memory rollbackData
    ) external onlyRole(MIGRATION_ADMIN_ROLE) returns (uint256) {
        require(bytes(name).length > 0, "Empty migration name");
        require(bytes(description).length > 0, "Empty description");
        require(bytes(fromVersion).length > 0, "Empty from version");
        require(bytes(toVersion).length > 0, "Empty to version");
        require(dataTypes.length > 0, "No data types specified");
        require(contractsToMigrate.length > 0, "No contracts to migrate");
        require(estimatedRecords > 0, "Invalid estimated records");

        migrationCounter++;
        uint256 id = migrationCounter;

        // Field-by-field assignment instead of struct literal!
        Migration storage m = migrations[id];
        m.id = id;
        m.name = name;
        m.description = description;
        m.fromVersion = fromVersion;
        m.toVersion = toVersion;
        for (uint256 i; i < dataTypes.length; i++) {
            m.dataTypes.push(dataTypes[i]);
        }
        for (uint256 i; i < contractsToMigrate.length; i++) {
            m.contractsToMigrate.push(contractsToMigrate[i]);
        }
        m.migrationExecutor = msg.sender;
        m.plannedAt = block.timestamp;
        m.startedAt = 0;
        m.completedAt = 0;
        m.status = MigrationStatus.Planned;
        m.totalRecords = estimatedRecords;
        m.migratedRecords = 0;
        m.failedRecords = 0;
        m.hasRollbackPlan = rollbackData.length > 0;
        m.rollbackData = rollbackData;
        m.errorMessage = "";
        m.migrationHash = keccak256(abi.encodePacked(name, contractsToMigrate, block.timestamp));

        activeMigrations.push(id);

        verificationLogger.logEvent("MIGRATION_PLANNED", msg.sender, m.migrationHash);
        emit MigrationPlanned(id, name, msg.sender);
        return id;
    }

    function startMigration(uint256 id) external onlyRole(MIGRATION_ADMIN_ROLE) nonReentrant {
        require(!emergencyPauseEnabled, "Emergency pause enabled");
        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.Planned || m.status == MigrationStatus.Paused, "InvalidMigrationStatus");
        require(m.migrationExecutor == msg.sender, "NotAuthorized");

        for (uint256 i; i < m.contractsToMigrate.length; i++) {
            _createStateSnapshot(m.contractsToMigrate[i]);
        }

        m.status = MigrationStatus.InProgress;
        m.startedAt = block.timestamp;

        verificationLogger.logEvent("MIGRATION_STARTED", msg.sender, m.migrationHash);
        emit MigrationStarted(id, m.totalRecords);
    }

    function executeBatchMigration(uint256 id, uint256 batchNumber, bytes memory batchData, uint256 recordCount)
        external
        onlyRole(MIGRATION_ADMIN_ROLE)
    {
        require(batchData.length > 0, "Empty batch data");
        require(recordCount > 0, "Invalid record count");
        require(recordCount <= maxBatchSize, "Batch too large");

        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.InProgress, "Migration not in progress");

        bytes32 hash = keccak256(batchData);
        bool success;
        string memory errorDetails;

        try this.processBatchData(batchData) {
            m.migratedRecords += recordCount;
            success = true;
        } catch Error(string memory err) {
            m.failedRecords += recordCount;
            success = false;
            errorDetails = err;
        } catch {
            m.failedRecords += recordCount;
            success = false;
            errorDetails = "UnknownError";
        }

        migrationBatches[id].push(
            BatchMigration({
                migrationId: id,
                batchNumber: batchNumber,
                recordCount: recordCount,
                dataHash: hash,
                processedAt: block.timestamp,
                isSuccessful: success,
                errorDetails: errorDetails
            })
        );

        verificationLogger.logEvent(success ? "BATCH_MIGRATION_SUCCESS" : "BATCH_MIGRATION_FAILED", msg.sender, hash);
        emit BatchMigrated(id, batchNumber, recordCount);
    }

    function completeMigration(uint256 id) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.InProgress, "NotInProgress");
        require(m.migrationExecutor == msg.sender, "NotAuthorized");

        m.status = MigrationStatus.Completed;
        m.completedAt = block.timestamp;
        verificationLogger.logEvent("MIGRATION_COMPLETED", msg.sender, m.migrationHash);
        emit MigrationCompleted(id, m.migratedRecords);

        _removeActiveMigration(id);

        for (uint256 i; i < m.contractsToMigrate.length; i++) {
            string memory name = _getContractName(m.contractsToMigrate[i]);
            contractVersions[name] = m.toVersion;
        }
    }

    function pauseMigration(uint256 id, string memory reason) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.InProgress, "NotInProgress");
        m.status = MigrationStatus.Paused;
        verificationLogger.logEvent("MIGRATION_PAUSED", msg.sender, keccak256(bytes(reason)));
        emit MigrationPaused(id, msg.sender);
    }

    function resumeMigration(uint256 id) external onlyRole(MIGRATION_ADMIN_ROLE) {
        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.Paused, "NotPaused");
        require(!emergencyPauseEnabled, "SystemPaused");
        m.status = MigrationStatus.InProgress;
        verificationLogger.logEvent("MIGRATION_RESUMED", msg.sender, m.migrationHash);
        emit MigrationResumed(id, msg.sender);
    }

    function rollbackMigration(uint256 id, string memory reason) external onlyRole(MIGRATION_ADMIN_ROLE) nonReentrant {
        Migration storage m = migrations[id];
        require(m.status == MigrationStatus.Completed || m.status == MigrationStatus.Failed, "NotRollbackable");
        require(m.hasRollbackPlan, "NoRollbackPlan");
        require(block.timestamp <= m.completedAt + rollbackWindow, "WindowExpired");

        m.status = MigrationStatus.Rollback;
        _executeRollback(id, m.rollbackData);
        for (uint256 i; i < m.contractsToMigrate.length; i++) {
            _restoreStateSnapshot(m.contractsToMigrate[i]);
        }
        verificationLogger.logEvent("ROLLBACK_EXECUTED", msg.sender, m.migrationHash);
        emit RollbackExecuted(id, reason);
    }

    function emergencyPause(string memory reason) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyPauseEnabled = true;
        verificationLogger.logEvent("EMERGENCY_PAUSE", msg.sender, keccak256(bytes(reason)));
        emit EmergencyPause(msg.sender, reason);
    }

    function emergencyResume() external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyPauseEnabled = false;
        verificationLogger.logEvent("EMERGENCY_RESUME", msg.sender, bytes32(0));
        emit EmergencyResume(msg.sender);
    }

    function processBatchData(bytes memory data) external view {
        require(msg.sender == address(this), "InternalOnly");
        require(data.length > 0, "EmptyBatch");
    }

    function _executeRollback(uint256, bytes memory) private {}

    function _createStateSnapshot(address c) private returns (uint256) {
        snapshotCounter++;
        uint256 id = snapshotCounter;
        bytes memory st = abi.encodePacked("snap", c, block.timestamp);
        bytes32 h = keccak256(st);
        stateSnapshots[id] = StateSnapshot({
            snapshotId: id,
            contractName: _getContractName(c),
            contractState: st,
            stateHash: h,
            blockNumber: block.number,
            timestamp: block.timestamp,
            isActive: true
        });
        emit StateSnapshotEvent(id, _getContractName(c), h);
        return id;
    }

    function _restoreStateSnapshot(address c) private {
        string memory name = _getContractName(c);
        for (uint256 i = snapshotCounter; i > 0; i--) {
            StateSnapshot storage s = stateSnapshots[i];
            if (keccak256(bytes(s.contractName)) == keccak256(bytes(name)) && s.isActive) {
                s.isActive = false;
                break;
            }
        }
    }

    function backupData(string memory cn, string memory dt, bytes memory d)
        external
        onlyRole(MIGRATION_ADMIN_ROLE)
        returns (bytes32)
    {
        bytes32 h = keccak256(abi.encodePacked(cn, dt, d, block.timestamp));
        dataBackups[h] = DataBackup(cn, dt, d, h, block.timestamp, contractVersions[cn], false);
        verificationLogger.logEvent("DATA_BACKED_UP", msg.sender, h);
        emit DataBackedUp(cn, dt, h);
        return h;
    }

    function restoreData(bytes32 h) external onlyRole(MIGRATION_ADMIN_ROLE) {
        DataBackup storage b = dataBackups[h];
        require(b.backupHash == h, "NoBackup");
        require(!b.isRestored, "AlreadyRestored");
        b.isRestored = true;
        verificationLogger.logEvent("DATA_RESTORED", msg.sender, h);
        emit DataRestored(b.contractName, h);
    }

    function setMaxBatchSize(uint256 s) external onlyRole(MIGRATION_ADMIN_ROLE) {
        require(s > 0 && s <= 10000, "InvalidSize");
        maxBatchSize = s;
    }

    function setMigrationTimeout(uint256 t) external onlyRole(MIGRATION_ADMIN_ROLE) {
        require(t >= 1 hours && t <= 168 hours, "InvalidTimeout");
        migrationTimeout = t;
    }

    function setRollbackWindow(uint256 w) external onlyRole(MIGRATION_ADMIN_ROLE) {
        require(w >= 1 days && w <= 30 days, "InvalidWindow");
        rollbackWindow = w;
    }

    function authorizeContract(address c, bool a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        authorizedMigrationContracts[c] = a;
    }

    function _removeActiveMigration(uint256 id) private {
        for (uint256 i; i < activeMigrations.length; i++) {
            if (activeMigrations[i] == id) {
                activeMigrations[i] = activeMigrations[activeMigrations.length - 1];
                activeMigrations.pop();
                break;
            }
        }
    }

    function _getContractName(address c) private pure returns (string memory) {
        return string(abi.encodePacked("Contract_", c));
    }
}

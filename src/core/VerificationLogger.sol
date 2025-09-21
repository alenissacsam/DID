// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title VerificationLogger
 * @author alenissacsam
 * @notice Logging contract for verification events across the System
 */
contract VerificationLogger is AccessControl {
    /*//////////////////////////////////////////////////////////////
                        VARIABLES & STRUTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant LOGGER_ROLE = keccak256("LOGGER_ROLE");

    struct LogEntry {
        uint256 id;
        string eventType;
        address user;
        address contractAddress;
        bytes32 dataHash;
        uint256 timestamp;
        uint256 blockNumber;
        bool isArchived; // For long-term storage management
    }

    mapping(uint256 => LogEntry) public logs;
    mapping(address => uint256[]) public userLogs;
    mapping(string => uint256[]) public eventTypeLogs;
    mapping(address => uint256[]) public contractLogs;

    uint256 public logCounter;
    uint256 public archiveThreshold = 1000000; // Archive logs older than this ID

    event EventLogged(
        uint256 indexed logId, string indexed eventType, address indexed user, address contractAddress, bytes32 dataHash
    );
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/
    event LogsArchived(uint256 fromId, uint256 toId);

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LOGGER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function logEvent(string memory eventType, address user, bytes32 dataHash) external onlyRole(LOGGER_ROLE) {
        require(bytes(eventType).length > 0, "Empty event type");
        require(user != address(0), "Invalid user address");

        logCounter++;

        LogEntry memory newLog = LogEntry({
            id: logCounter,
            eventType: eventType,
            user: user,
            contractAddress: msg.sender,
            dataHash: dataHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            isArchived: false
        });

        logs[logCounter] = newLog;
        userLogs[user].push(logCounter);
        eventTypeLogs[eventType].push(logCounter);
        contractLogs[msg.sender].push(logCounter);

        emit EventLogged(logCounter, eventType, user, msg.sender, dataHash);
    }

    function batchLogEvents(string[] memory eventTypes, address[] memory users, bytes32[] memory dataHashes)
        external
        onlyRole(LOGGER_ROLE)
    {
        require(eventTypes.length == users.length && users.length == dataHashes.length, "Array lengths must match");
        require(eventTypes.length > 0 && eventTypes.length <= 50, "Invalid batch size");

        unchecked {
            for (uint256 i = 0; i < eventTypes.length; ++i) {
                require(bytes(eventTypes[i]).length > 0, "Empty event type");
                require(users[i] != address(0), "Invalid user address");

                logCounter++;

                LogEntry memory newLog = LogEntry({
                    id: logCounter,
                    eventType: eventTypes[i],
                    user: users[i],
                    contractAddress: msg.sender,
                    dataHash: dataHashes[i],
                    timestamp: block.timestamp,
                    blockNumber: block.number,
                    isArchived: false
                });

                logs[logCounter] = newLog;
                userLogs[users[i]].push(logCounter);
                eventTypeLogs[eventTypes[i]].push(logCounter);
                contractLogs[msg.sender].push(logCounter);

                emit EventLogged(logCounter, eventTypes[i], users[i], msg.sender, dataHashes[i]);
            }
        }
    }

    function archiveLogs(uint256 fromId, uint256 toId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(fromId <= toId && toId <= logCounter, "Invalid range");
        require(toId < logCounter - archiveThreshold, "Cannot archive recent logs");

        for (uint256 i = fromId; i <= toId; i++) {
            if (logs[i].id != 0) {
                // Check if log exists
                logs[i].isArchived = true;
            }
        }

        emit LogsArchived(fromId, toId);
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getUserLogs(address user) external view returns (uint256[] memory) {
        return userLogs[user];
    }

    function getUserLogsInRange(address user, uint256 fromTimestamp, uint256 toTimestamp)
        external
        view
        returns (LogEntry[] memory)
    {
        uint256[] memory userLogIds = userLogs[user];
        uint256 count = 0;

        // First pass: count matching logs
        for (uint256 i = 0; i < userLogIds.length; i++) {
            LogEntry memory log = logs[userLogIds[i]];
            if (log.timestamp >= fromTimestamp && log.timestamp <= toTimestamp) {
                count++;
            }
        }

        // Second pass: collect matching logs
        LogEntry[] memory result = new LogEntry[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < userLogIds.length; i++) {
            LogEntry memory log = logs[userLogIds[i]];
            if (log.timestamp >= fromTimestamp && log.timestamp <= toTimestamp) {
                result[index] = log;
                index++;
            }
        }

        return result;
    }

    function getEventTypeLogs(string memory eventType) external view returns (uint256[] memory) {
        return eventTypeLogs[eventType];
    }

    function getContractLogs(address contractAddress) external view returns (uint256[] memory) {
        return contractLogs[contractAddress];
    }

    function getLogsInRange(uint256 fromId, uint256 toId) external view returns (LogEntry[] memory) {
        require(fromId <= toId && toId <= logCounter, "Invalid range");

        uint256 length = toId - fromId + 1;
        LogEntry[] memory result = new LogEntry[](length);

        for (uint256 i = 0; i < length; i++) {
            result[i] = logs[fromId + i];
        }

        return result;
    }

    function getLogsByTimeRange(uint256 fromTime, uint256 toTime) external view returns (LogEntry[] memory) {
        require(toTime <= block.timestamp, "toTime cannot be in the future");
        require(fromTime <= toTime, "Invalid time range");

        uint256 count = 0;

        // First pass: count logs in time range
        for (uint256 i = 1; i <= logCounter; i++) {
            if (logs[i].timestamp >= fromTime && logs[i].timestamp <= toTime) {
                count++;
            }
        }

        LogEntry[] memory result = new LogEntry[](count);
        uint256 index = 0;

        // Second pass: collect logs
        for (uint256 i = 1; i <= logCounter; i++) {
            if (logs[i].timestamp >= fromTime && logs[i].timestamp <= toTime) {
                result[index] = logs[i];
                index++;
            }
        }

        return result;
    }

    function getLogsByEventTypeAndTimeRange(string memory eventType, uint256 fromTime, uint256 toTime)
        external
        view
        returns (LogEntry[] memory)
    {
        uint256[] memory eventLogIds = eventTypeLogs[eventType];
        uint256 count = 0;

        // First pass: count matching logs
        for (uint256 i = 0; i < eventLogIds.length; i++) {
            LogEntry memory log = logs[eventLogIds[i]];
            if (log.timestamp >= fromTime && log.timestamp <= toTime) {
                count++;
            }
        }

        // Second pass: collect matching logs
        LogEntry[] memory result = new LogEntry[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < eventLogIds.length; i++) {
            LogEntry memory log = logs[eventLogIds[i]];
            if (log.timestamp >= fromTime && log.timestamp <= toTime) {
                result[index] = log;
                index++;
            }
        }

        return result;
    }

    function getTotalLogs() external view returns (uint256) {
        return logCounter;
    }

    function getLogStats() external view returns (uint256 totalLogs, uint256 archivedLogs, uint256 activeLogs) {
        totalLogs = logCounter;

        uint256 archived = 0;
        for (uint256 i = 1; i <= logCounter; i++) {
            if (logs[i].isArchived) {
                archived++;
            }
        }

        archivedLogs = archived;
        activeLogs = totalLogs - archived;
    }

    function setArchiveThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        archiveThreshold = newThreshold;
    }

    function verifyLogIntegrity(uint256 logId) external view returns (bool) {
        LogEntry memory log = logs[logId];
        if (log.id != logId) return false;
        if (log.timestamp == 0) return false;
        return true;
    }
}

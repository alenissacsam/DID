// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IChainRegistry {
    enum BridgeStatus {
        Active,
        Paused,
        Deprecated
    }

    struct ChainConfig {
        uint16 chainId;
        string chainName;
        address endpoint;
        address trustedRemote;
        BridgeStatus status;
        uint256 minConfirmations;
        uint256 maxGasLimit;
        uint256 baseFee;
        bool isActive;
        uint256 lastSyncTime;
    }

    function getChainConfig(
        uint16 chainId
    ) external view returns (ChainConfig memory);

    function isChainActive(uint16 chainId) external view returns (bool);

    function getActiveChains() external view returns (uint16[] memory);

    // Admin functions
    function setChainConfig(
        uint16 chainId,
        string calldata chainName,
        address endpoint,
        address trustedRemote,
        uint256 minConfirmations,
        uint256 maxGasLimit,
        uint256 baseFee
    ) external;

    function setChainStatus(uint16 chainId, BridgeStatus newStatus) external;

    function pauseAll(string calldata reason) external;

    function unpauseAll() external;
}

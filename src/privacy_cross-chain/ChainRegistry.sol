// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IChainRegistry.sol";

contract ChainRegistry is AccessControl, IChainRegistry {
    error InvalidAddress();
    error InvalidParam();

    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");

    mapping(uint16 => ChainConfig) private _chains;
    uint16[] private _activeChainIds;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BRIDGE_ADMIN_ROLE, msg.sender);
    }

    function getChainConfig(
        uint16 chainId
    ) external view returns (ChainConfig memory) {
        return _chains[chainId];
    }

    function isChainActive(uint16 chainId) external view returns (bool) {
        ChainConfig memory c = _chains[chainId];
        return c.isActive && c.status == BridgeStatus.Active;
    }

    function getActiveChains() external view returns (uint16[] memory) {
        return _activeChainIds;
    }

    function setChainConfig(
        uint16 chainId,
        string calldata chainName,
        address endpoint,
        address trustedRemote,
        uint256 minConfirmations,
        uint256 maxGasLimit,
        uint256 baseFee
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (chainId == 0) revert InvalidParam();
        if (bytes(chainName).length == 0) revert InvalidParam();
        if (endpoint == address(0)) revert InvalidAddress();
        if (trustedRemote == address(0)) revert InvalidAddress();
        if (maxGasLimit == 0) revert InvalidParam();

        bool isNew = !_chains[chainId].isActive;

        _chains[chainId] = ChainConfig({
            chainId: chainId,
            chainName: chainName,
            endpoint: endpoint,
            trustedRemote: trustedRemote,
            status: BridgeStatus.Active,
            minConfirmations: minConfirmations,
            maxGasLimit: maxGasLimit,
            baseFee: baseFee,
            isActive: true,
            lastSyncTime: block.timestamp
        });

        if (isNew) _activeChainIds.push(chainId);
    }

    function setChainStatus(
        uint16 chainId,
        BridgeStatus newStatus
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (!_chains[chainId].isActive) revert InvalidParam();
        _chains[chainId].status = newStatus;
    }

    function pauseAll(
        string calldata /*reason*/
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        for (uint256 i = 0; i < _activeChainIds.length; i++) {
            _chains[_activeChainIds[i]].status = BridgeStatus.Paused;
        }
    }

    function unpauseAll() external onlyRole(BRIDGE_ADMIN_ROLE) {
        for (uint256 i = 0; i < _activeChainIds.length; i++) {
            if (_chains[_activeChainIds[i]].status == BridgeStatus.Paused) {
                _chains[_activeChainIds[i]].status = BridgeStatus.Active;
            }
        }
    }
}

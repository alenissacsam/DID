// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../../interfaces/IVerificationLogger.sol";
import {ISessionKeyManager} from "../../interfaces/ISessionKeyManager.sol";

contract SessionKeyManager is
    AccessControl,
    ReentrancyGuard,
    ISessionKeyManager
{
    error NotOwner();
    error InvalidParam();
    error NotManager();

    bytes32 public constant ADMIN_ROLE = keccak256("SESSION_ADMIN_ROLE");

    IVerificationLogger public immutable logger;
    address public immutable authorizedManager;

    mapping(address => mapping(address => SessionKey)) public sessionKeys; // wallet => sessionKey => data
    mapping(address => address[]) public walletSessionKeys;

    constructor(address _logger, address _manager) {
        if (_logger == address(0) || _manager == address(0))
            revert InvalidParam();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        logger = IVerificationLogger(_logger);
        authorizedManager = _manager;
    }

    modifier onlyManager() {
        if (msg.sender != authorizedManager) revert NotManager();
        _;
    }

    function addSessionKey(
        address wallet,
        address sessionKey,
        uint256 validUntil,
        uint256 spendingLimit,
        string[] calldata allowedFunctions,
        address[] calldata allowedContracts
    ) external override nonReentrant onlyManager {
        if (wallet == address(0) || sessionKey == address(0))
            revert InvalidParam();
        if (validUntil <= block.timestamp) revert InvalidParam();

        sessionKeys[wallet][sessionKey] = SessionKey({
            keyAddress: sessionKey,
            validUntil: validUntil,
            spendingLimit: spendingLimit,
            spentAmount: 0,
            isActive: true,
            allowedFunctions: allowedFunctions,
            allowedContracts: allowedContracts
        });

        walletSessionKeys[wallet].push(sessionKey);

        logger.logEvent(
            "SKA",
            msg.sender,
            keccak256(abi.encodePacked(wallet, sessionKey, validUntil))
        );
        emit SKA(wallet, sessionKey, validUntil);
    }

    function revokeSessionKey(
        address wallet,
        address sessionKey
    ) external override nonReentrant onlyManager {
        if (wallet == address(0) || sessionKey == address(0))
            revert InvalidParam();
        if (!sessionKeys[wallet][sessionKey].isActive) revert InvalidParam();

        sessionKeys[wallet][sessionKey].isActive = false;
        logger.logEvent(
            "SKR",
            msg.sender,
            keccak256(abi.encodePacked(wallet, sessionKey))
        );
        emit SKR(wallet, sessionKey);
    }

    function isSessionKeyValid(
        address wallet,
        address sessionKey
    ) external view override returns (bool) {
        SessionKey memory key = sessionKeys[wallet][sessionKey];
        return key.isActive && block.timestamp <= key.validUntil;
    }

    function getSessionKeys(
        address wallet
    ) external view override returns (address[] memory) {
        return walletSessionKeys[wallet];
    }

    function getSessionKey(
        address wallet,
        address sessionKey
    ) external view override returns (SessionKey memory) {
        return sessionKeys[wallet][sessionKey];
    }
}

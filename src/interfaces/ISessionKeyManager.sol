// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ISessionKeyManager {
    struct SessionKey {
        address keyAddress;
        uint256 validUntil;
        uint256 spendingLimit;
        uint256 spentAmount;
        bool isActive;
        string[] allowedFunctions;
        address[] allowedContracts;
    }

    event SKA(
        address indexed wallet,
        address indexed sessionKey,
        uint256 validUntil
    );
    event SKR(address indexed wallet, address indexed sessionKey);

    function addSessionKey(
        address wallet,
        address sessionKey,
        uint256 validUntil,
        uint256 spendingLimit,
        string[] calldata allowedFunctions,
        address[] calldata allowedContracts
    ) external;

    function revokeSessionKey(address wallet, address sessionKey) external;

    function isSessionKeyValid(
        address wallet,
        address sessionKey
    ) external view returns (bool);

    function getSessionKeys(
        address wallet
    ) external view returns (address[] memory);

    function getSessionKey(
        address wallet,
        address sessionKey
    ) external view returns (SessionKey memory);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IRecoveryManager {
    struct Recovery {
        uint256 id;
        address wallet;
        address newOwner;
        address[] approvedGuardians;
        uint256 requestedAt;
        uint256 executeAfter;
        bool isExecuted;
        bool isCancelled;
        string reason;
    }

    event RRQ(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed newOwner
    );
    event RCF(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed guardian
    );
    event REX(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed oldOwner
    );

    function requestRecovery(
        address wallet,
        address newOwner,
        string calldata reason,
        uint256 delay,
        address owner,
        address guardian
    ) external returns (uint256);

    function confirmRecovery(
        uint256 recoveryId,
        address wallet,
        address owner,
        address guardian
    ) external;

    function executeRecovery(
        uint256 recoveryId,
        address wallet,
        address owner
    ) external returns (address newOwner);

    function getRecoveriesCount(address wallet) external view returns (uint256);
}

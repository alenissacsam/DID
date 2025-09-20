// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ITrustScore
 * @notice Interface for the TrustScore contract
 */
interface ITrustScore {
    function getTrustScore(address user) external view returns (uint256);

    function updateScoreForGaslessTransaction(address user) external;

    function initializeUserScore(address user, uint256 initialScore) external;

    function initializeUser(address user) external;

    function updateScore(
        address user,
        int256 delta,
        string memory reason
    ) external;

    function unlockScore(address user) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IVerificationLogger
 * @notice Interface for the VerificationLogger contract
 */
interface IVerificationLogger {
    function logEvent(string memory eventType, address user, bytes32 dataHash) external;
}

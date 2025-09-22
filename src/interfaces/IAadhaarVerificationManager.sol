// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IAadhaarVerificationManager {
    function isAadhaarVerified(address user) external view returns (bool);
}

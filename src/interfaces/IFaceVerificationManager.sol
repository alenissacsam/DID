// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IFaceVerificationManager {
    function isFaceVerified(address user) external view returns (bool);
}

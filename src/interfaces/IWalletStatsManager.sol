// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IWalletStatsManager {
    struct UserOpStats {
        uint256 totalOps;
        uint256 successfulOps;
        uint256 failedOps;
        uint256 totalGasUsed;
        uint256 totalFeesPaid;
        uint256 lastOpTimestamp;
    }

    function recordUserOp(
        address wallet,
        bool success,
        uint256 gasUsed,
        uint256 feesPaid
    ) external;

    function getStats(
        address wallet
    ) external view returns (UserOpStats memory);
}

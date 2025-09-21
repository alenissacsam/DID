// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IWalletStatsManager} from "../interfaces/IWalletStatsManager.sol";

contract WalletStatsManager is IWalletStatsManager {
    mapping(address => UserOpStats) public stats;

    function recordUserOp(
        address wallet,
        bool success,
        uint256 gasUsed,
        uint256 feesPaid
    ) external {
        UserOpStats storage s = stats[wallet];
        s.totalOps++;
        if (success) s.successfulOps++;
        else s.failedOps++;
        s.totalGasUsed += gasUsed;
        s.totalFeesPaid += feesPaid;
        s.lastOpTimestamp = block.timestamp;
    }

    function getStats(
        address wallet
    ) external view returns (UserOpStats memory) {
        return stats[wallet];
    }
}

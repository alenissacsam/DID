// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IRecoveryManager} from "../../interfaces/IRecoveryManager.sol";
import "../../interfaces/IVerificationLogger.sol";
import "../../interfaces/IGuardianManager.sol";

contract RecoveryManager is IRecoveryManager {
    error InvalidParam();
    error RecoveryNotActive();
    error DelayNotMet();
    error NotGuardian();
    error ThresholdNotMet();

    IVerificationLogger public immutable logger;
    IGuardianManager public immutable guardianManager;

    mapping(address => Recovery[]) public recoveries;
    uint256 public recoveryCounter;

    constructor(address _logger, address _guardianManager) {
        logger = IVerificationLogger(_logger);
        guardianManager = IGuardianManager(_guardianManager);
    }

    function requestRecovery(
        address wallet,
        address newOwner,
        string calldata reason,
        uint256 delay,
        address owner,
        address guardian
    ) external override returns (uint256) {
        if (
            wallet == address(0) ||
            newOwner == address(0) ||
            owner == address(0) ||
            guardian == address(0)
        ) {
            revert InvalidParam();
        }
        if (!guardianManager.isGuardian(owner, guardian)) revert NotGuardian();

        recoveryCounter++;
        uint256 recoveryId = recoveryCounter;

        Recovery memory newRecovery = Recovery({
            id: recoveryId,
            wallet: wallet,
            newOwner: newOwner,
            approvedGuardians: new address[](1),
            requestedAt: block.timestamp,
            executeAfter: block.timestamp + delay,
            isExecuted: false,
            isCancelled: false,
            reason: reason
        });

        newRecovery.approvedGuardians[0] = guardian;
        recoveries[wallet].push(newRecovery);

        emit RRQ(recoveryId, wallet, newOwner);
        return recoveryId;
    }

    function confirmRecovery(
        uint256 recoveryId,
        address wallet,
        address owner,
        address guardian
    ) external override {
        Recovery[] storage walletRecoveries = recoveries[wallet];
        if (!(recoveryId > 0 && recoveryId <= walletRecoveries.length))
            revert InvalidParam();
        Recovery storage recovery = walletRecoveries[recoveryId - 1];
        if (recovery.isExecuted || recovery.isCancelled)
            revert RecoveryNotActive();
        if (!guardianManager.isGuardian(owner, guardian)) revert NotGuardian();

        // Check if already approved
        for (uint256 i = 0; i < recovery.approvedGuardians.length; i++) {
            if (recovery.approvedGuardians[i] == guardian)
                revert InvalidParam();
        }

        // Add guardian approval
        address[] memory newApprovals = new address[](
            recovery.approvedGuardians.length + 1
        );
        for (uint256 i = 0; i < recovery.approvedGuardians.length; i++) {
            newApprovals[i] = recovery.approvedGuardians[i];
        }
        newApprovals[recovery.approvedGuardians.length] = guardian;
        recovery.approvedGuardians = newApprovals;

        emit RCF(recoveryId, wallet, guardian);
    }

    function executeRecovery(
        uint256 recoveryId,
        address wallet,
        address owner
    ) external override returns (address newOwner) {
        Recovery[] storage walletRecoveries = recoveries[wallet];
        if (!(recoveryId > 0 && recoveryId <= walletRecoveries.length))
            revert InvalidParam();

        Recovery storage recovery = walletRecoveries[recoveryId - 1];
        if (recovery.isExecuted || recovery.isCancelled)
            revert RecoveryNotActive();
        if (block.timestamp < recovery.executeAfter) revert DelayNotMet();

        (, uint256 threshold, ) = guardianManager.getGuardianSet(owner);
        if (recovery.approvedGuardians.length < threshold)
            revert ThresholdNotMet();

        recovery.isExecuted = true;
        newOwner = recovery.newOwner;
        emit REX(recoveryId, wallet, owner);
    }

    function getRecoveriesCount(
        address wallet
    ) external view override returns (uint256) {
        return recoveries[wallet].length;
    }
}

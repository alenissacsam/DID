// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IGuardianManager
 * @notice Interface for the GuardianManager contract
 */
interface IGuardianManager {
    function isGuardian(address user, address guardian) external view returns (bool);

    function getGuardianSet(address user)
        external
        view
        returns (address[] memory guardians, uint256 threshold, bool isSetup);
}

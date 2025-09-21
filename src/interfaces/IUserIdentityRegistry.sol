// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IUserIdentityRegistry
 * @notice Interface for the UserIdentityRegistry contract
 */
interface IUserIdentityRegistry {
    enum VerificationKind {
        Face,
        Aadhaar,
        Income
    }

    function isVerified(address user) external view returns (bool);

    function getUserCommitment(address user) external view returns (bytes32);

    function isRegistered(address user) external view returns (bool);

    function unlockIdentity(address user) external;

    function getVerificationStatus(address user)
        external
        view
        returns (bool faceVerified, bool aadhaarVerified, bool incomeVerified, uint256 verificationLevel);

    function updateVerificationStatus(address user, VerificationKind kind, bool status) external;

    function isIdentityLocked(address user) external view returns (bool);

    function updateIdentityCommitment(address user, bytes32 newCommitment) external;

    function deregisterIdentity(address user) external;
}

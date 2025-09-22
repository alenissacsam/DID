// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICertificateManager {
    function getCertificatesByHolder(
        address holder
    ) external view returns (uint256[] memory);

    function verifyCertificate(
        uint256 certificateId
    ) external view returns (bool);

    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;
}

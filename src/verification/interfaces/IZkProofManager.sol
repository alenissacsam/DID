// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZkProofManager {
    function anchorRoot(bytes32 root) external;

    function revokeRoot(bytes32 root) external;
}

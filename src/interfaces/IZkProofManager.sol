// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZkProofManager {
    // Anchor a Merkle root as valid for proof verification
    function anchorRoot(bytes32 root) external;

    // Revoke a previously anchored Merkle root
    function revokeRoot(bytes32 root) external;
}

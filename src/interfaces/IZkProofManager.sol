// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZkProofManager {
    // Anchor a Merkle root as valid for proof verification
    function anchorRoot(bytes32 root) external;

    // Revoke a previously anchored Merkle root
    function revokeRoot(bytes32 root) external;

    // Generic verification entry point for any registered proof type
    // Assumes publicSignals[0] is the Merkle root
    function verifyProof(
        uint256 typeId,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external;
}

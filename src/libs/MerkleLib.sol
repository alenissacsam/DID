// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library MerkleLib {
    function hashPair(bytes32 a, bytes32 b) public pure returns (bytes32) {
        return
            a < b
                ? keccak256(abi.encodePacked(a, b))
                : keccak256(abi.encodePacked(b, a));
    }

    function computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256 index
    ) public pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (index % 2 == 0) {
                computedHash = hashPair(computedHash, proofElement);
            } else {
                computedHash = hashPair(proofElement, computedHash);
            }
            index = index / 2;
        }
        return computedHash;
    }

    function calculateBatchRoot(
        bytes32[] memory credentialHashes
    ) public pure returns (bytes32) {
        if (credentialHashes.length == 0) return bytes32(0);
        if (credentialHashes.length == 1) return credentialHashes[0];

        bytes32[] memory currentLevel = credentialHashes;
        while (currentLevel.length > 1) {
            uint256 nextLevelLength = (currentLevel.length + 1) / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelLength);
            for (uint256 i = 0; i < nextLevelLength; i++) {
                bytes32 left = currentLevel[i * 2];
                bytes32 right = (i * 2 + 1 < currentLevel.length)
                    ? currentLevel[i * 2 + 1]
                    : bytes32(0);
                nextLevel[i] = hashPair(left, right);
            }
            currentLevel = nextLevel;
        }
        return currentLevel[0];
    }
}

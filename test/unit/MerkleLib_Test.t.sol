// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
import {MerkleLib} from "../../src/libs/MerkleLib.sol";

contract MerkleLib_Test is Test {
    function test_merkle_proof_success_and_fail() public {
        // Build a simple 3-leaf tree (pad to 4) manually
        bytes32 l1 = keccak256(abi.encodePacked("A"));
        bytes32 l2 = keccak256(abi.encodePacked("B"));
        bytes32 l3 = keccak256(abi.encodePacked("C"));
        bytes32 l4 = bytes32(0);
        bytes32 p1 = keccak256(abi.encodePacked(l1, l2));
        bytes32 p2 = keccak256(abi.encodePacked(l3, l4));
        bytes32 root = keccak256(abi.encodePacked(p1, p2));

        // Proof for leaf B (l2): sibling is l1, then sibling hash is p2
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = l1; // level 1 sibling
        proof[1] = p2; // level 2 sibling

        bytes32 computed = MerkleLib.computeMerkleRoot(l2, proof, 1); // index 1 (second leaf)
        assertEq(computed, root);

        // Wrong leaf should not match root
        bytes32 wrong = MerkleLib.computeMerkleRoot(l3, proof, 2);
        assertTrue(wrong != root);
    }
}

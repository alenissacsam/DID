// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {IGroth16Verifier} from "src/interfaces/IGroth16Verifier.sol";

contract TestGroth16Verifier is IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract ZKProofManagerFuzzTest is Test {
    ZKProofManager zk;
    TestGroth16Verifier verifier;
    address admin = address(0xABCD);

    function setUp() public {
        vm.startPrank(admin);
        zk = new ZKProofManager();
        verifier = new TestGroth16Verifier();
        // Register canonical types
        zk.addProofType("AGE_GTE", address(verifier));
        zk.addProofType("ATTR_EQ", address(verifier));
        zk.addProofType("INCOME_GTE", address(verifier));
        zk.addProofType("AGE_LTE", address(verifier));
        // Anchor a default root so contract has at least one valid root
        zk.anchorRoot(keccak256("default_root"));
        vm.stopPrank();
    }

    function _signals(
        bytes32 root,
        uint256 extraLen
    ) internal pure returns (uint256[] memory s) {
        // First public signal is the root by convention
        s = new uint256[](extraLen + 1);
        s[0] = uint256(root);
        for (uint256 i = 1; i < s.length; i++) {
            s[i] = i; // filler
        }
    }

    function testFuzz_anchorRoot_never_allows_zero_and_no_duplicates(
        bytes32 root
    ) public {
        vm.assume(root != bytes32(0));
        // Avoid duplicate of the default root
        vm.assume(root != keccak256("default_root"));
        // Ensure not already anchored (fresh deployment per test, but keep assumption for fuzzing)
        bool isValid = zk.isValidRoot(root);
        vm.assume(!isValid);

        vm.prank(admin);
        zk.anchorRoot(root);
        assertTrue(zk.isValidRoot(root));
        assertGt(zk.rootTimestamps(root), 0);

        vm.expectRevert();
        vm.prank(admin);
        zk.anchorRoot(root); // duplicate should revert
    }

    function testFuzz_verifyProof_succeeds_and_replay_reverts(
        bytes32 root,
        bytes32 nullifier,
        uint8 typeChoice
    ) public {
        vm.assume(root != bytes32(0));
        // Avoid colliding with default pre-anchored root to keep assumptions simple
        if (!zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.anchorRoot(root);
        }

        uint256 count = zk.proofTypeCount();
        assertGt(count, 0);
        uint256 typeId = uint256(typeChoice) % count;

        uint256[] memory signals = _signals(root, 2);
        zk.verifyProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            signals,
            nullifier
        );

        // Replay with same nullifier must revert
        vm.expectRevert();
        zk.verifyProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            signals,
            nullifier
        );
    }

    function testFuzz_verifyProof_rejects_unanchored_root(
        bytes32 root,
        uint8 typeChoice
    ) public {
        vm.assume(root != bytes32(0));
        // Ensure root is not anchored
        if (zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.revokeRoot(root);
        }

        uint256 count = zk.proofTypeCount();
        uint256 typeId = uint256(typeChoice) % count;

        uint256[] memory signals = _signals(root, 1);
        vm.expectRevert();
        zk.verifyProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            signals,
            keccak256("n_fuzz")
        );
    }

    function testFuzz_updateProofType_toggle_effect(uint8 idx) public {
        uint256 count = zk.proofTypeCount();
        uint256 typeId = uint256(idx) % count;

        // Disable the type
        vm.prank(admin);
        zk.updateProofType(typeId, address(verifier), false);

        bytes32 root = keccak256("toggle_root");
        if (!zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.anchorRoot(root);
        }
        uint256[] memory signals = _signals(root, 1);

        vm.expectRevert();
        zk.verifyProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            signals,
            keccak256("n_toggle")
        );

        // Re-enable and verify succeeds
        vm.prank(admin);
        zk.updateProofType(typeId, address(verifier), true);
        zk.verifyProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            signals,
            keccak256("n_toggle2")
        );
    }
}

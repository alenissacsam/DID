// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {OfflineVerificationManager} from "src/verification/OfflineVerificationManager.sol";
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

contract OfflineVerificationManagerZkForwardFuzzTest is Test {
    OfflineVerificationManager off;
    ZKProofManager zk;
    TestGroth16Verifier verifier;
    address admin = address(0xBEEF);

    function setUp() public {
        vm.startPrank(admin);
        off = new OfflineVerificationManager(admin);
        zk = new ZKProofManager();
        verifier = new TestGroth16Verifier();
        zk.addProofType("AGE_GTE", address(verifier));
        zk.addProofType("ATTR_EQ", address(verifier));
        zk.addProofType("INCOME_GTE", address(verifier));
        zk.addProofType("AGE_LTE", address(verifier));
        zk.anchorRoot(keccak256("off_default_root"));
        off.setZkProofManager(address(zk));
        vm.stopPrank();
    }

    function _signals(
        bytes32 root,
        uint256 extra
    ) internal pure returns (uint256[] memory s) {
        s = new uint256[](1 + extra);
        s[0] = uint256(root);
        for (uint256 i = 1; i < s.length; i++) s[i] = i;
    }

    function testFuzz_verifyZkProof_succeeds(
        bytes32 root,
        bytes32 nullifier,
        uint8 typeChoice
    ) public {
        vm.assume(root != bytes32(0));
        if (!zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.anchorRoot(root);
        }
        uint256 count = zk.proofTypeCount();
        uint256 typeId = uint256(typeChoice) % count;
        off.verifyZkProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(root, 2),
            nullifier
        );
    }

    function testFuzz_verifyZkProof_replay_reverts(
        bytes32 root,
        bytes32 nullifier,
        uint8 typeChoice
    ) public {
        vm.assume(root != bytes32(0));
        if (!zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.anchorRoot(root);
        }
        uint256 count = zk.proofTypeCount();
        uint256 typeId = uint256(typeChoice) % count;
        uint256[] memory sigs = _signals(root, 1);
        off.verifyZkProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
        vm.expectRevert();
        off.verifyZkProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
    }

    function testFuzz_verifyZkProof_invalid_root_reverts(
        bytes32 root,
        uint8 typeChoice
    ) public {
        vm.assume(root != bytes32(0));
        // Ensure root not anchored
        if (zk.isValidRoot(root)) {
            vm.prank(admin);
            zk.revokeRoot(root);
        }
        uint256 count = zk.proofTypeCount();
        uint256 typeId = uint256(typeChoice) % count;
        vm.expectRevert();
        off.verifyZkProof(
            typeId,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(root, 0),
            keccak256("off_n1")
        );
    }
}

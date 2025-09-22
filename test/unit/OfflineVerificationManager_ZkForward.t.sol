// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {OfflineVerificationManager} from "src/verification/OfflineVerificationManager.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {IGroth16Verifier} from "src/interfaces/IGroth16Verifier.sol";

contract TestGroth16Verifier is IGroth16Verifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

contract OfflineVerificationManagerZkForwardTest is Test {
    OfflineVerificationManager off;
    ZKProofManager zk;
    TestGroth16Verifier verifier;
    address admin = address(0xAA);

    function setUp() public {
        vm.startPrank(admin);
        off = new OfflineVerificationManager(admin);
        zk = new ZKProofManager();
        verifier = new TestGroth16Verifier();
        // Register some types and anchor root
        zk.addProofType("AGE_GTE", address(verifier));
        zk.addProofType("ATTR_EQ", address(verifier));
        zk.addProofType("INCOME_GTE", address(verifier));
        zk.addProofType("AGE_LTE", address(verifier));
        zk.anchorRoot(keccak256("root"));
        off.setZkProofManager(address(zk));
        vm.stopPrank();
    }

    function _signals(bytes32 root) internal pure returns (uint256[] memory) {
        uint256[] memory s = new uint256[](2);
        s[0] = uint256(root);
        s[1] = 1;
        return s;
    }

    function test_verifyZkProof_success() public {
        off.verifyZkProof(
            2,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(keccak256("root")),
            keccak256("n1")
        );
    }

    function test_verifyZkProof_replay_reverts() public {
        bytes32 n = keccak256("n2");
        off.verifyZkProof(
            2,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(keccak256("root")),
            n
        );
        vm.expectRevert();
        off.verifyZkProof(
            2,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(keccak256("root")),
            n
        );
    }

    function test_verifyZkProof_invalid_root_reverts() public {
        vm.expectRevert();
        off.verifyZkProof(
            2,
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _signals(bytes32(uint256(0x1234))),
            keccak256("n3")
        );
    }
}

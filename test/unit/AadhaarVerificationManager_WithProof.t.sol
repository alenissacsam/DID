// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {AadhaarVerificationManager} from "src/verification/AadhaarVerificationManager.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {IGroth16Verifier} from "src/interfaces/IGroth16Verifier.sol";
import {IFaceVerificationManager} from "src/interfaces/IFaceVerificationManager.sol";

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

contract TestFaceManager is IFaceVerificationManager {
    function isFaceVerified(address) external pure returns (bool) {
        return true;
    }
}

contract AadhaarVerificationManagerWithProofTest is Test {
    ZKProofManager zk;
    AadhaarVerificationManager aadhaar;
    UserIdentityRegistry registry;
    TrustScore score;
    VerificationLogger logger;
    TestGroth16Verifier verifier;

    address admin = address(0xAA);
    address user = address(0xBEEF);

    function setUp() public {
        vm.startPrank(admin);
        logger = new VerificationLogger();
        score = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(score));
        // roles
        registry.grantRole(registry.DEFAULT_ADMIN_ROLE(), admin);
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), admin);
        score.grantRole(score.DEFAULT_ADMIN_ROLE(), admin);
        score.grantRole(score.SCORE_MANAGER_ROLE(), address(registry));
        logger.grantRole(logger.DEFAULT_ADMIN_ROLE(), admin);
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        logger.grantRole(LOGGER_ROLE, address(registry));
        logger.grantRole(LOGGER_ROLE, address(score));

        // deploy
        TestFaceManager face = new TestFaceManager();
        aadhaar = new AadhaarVerificationManager(
            address(logger),
            address(registry),
            address(score),
            address(face)
        );
        logger.grantRole(LOGGER_ROLE, address(aadhaar));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(aadhaar));
        score.grantRole(score.SCORE_MANAGER_ROLE(), address(aadhaar));

        // user
        registry.registerIdentity(user, bytes32("commit"));
        aadhaar.grantRole(aadhaar.UIDAI_ORACLE_ROLE(), admin);
        vm.stopPrank();

        // zk
        vm.startPrank(admin);
        zk = new ZKProofManager();
        verifier = new TestGroth16Verifier();
        zk.addProofType("AGE_GTE", address(verifier));
        zk.addProofType("ATTR_EQ", address(verifier));
        zk.addProofType("INCOME_GTE", address(verifier));
        zk.addProofType("AGE_LTE", address(verifier));
        zk.anchorRoot(keccak256("root"));
        aadhaar.setZkProofManager(address(zk));
        vm.stopPrank();
    }

    function _mkSignals(bytes32 root) internal pure returns (uint256[] memory) {
        uint256[] memory sigs = new uint256[](2);
        sigs[0] = uint256(root);
        sigs[1] = 777; // arbitrary
        return sigs;
    }

    function test_completeAadhaarVerificationWithProof_success() public {
        vm.startPrank(user);
        aadhaar.requestAadhaarVerification(
            bytes32("ah"),
            bytes32("otp"),
            "OTP"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        bytes32 nullifier = keccak256("nA1");
        aadhaar.completeAadhaarVerificationWithProof(
            user,
            new bytes(65),
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _mkSignals(keccak256("root")),
            nullifier
        );
        vm.stopPrank();
    }

    function test_completeAadhaarVerificationWithProof_replay_reverts() public {
        vm.startPrank(user);
        aadhaar.requestAadhaarVerification(
            bytes32("ah"),
            bytes32("otp"),
            "OTP"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        bytes32 nullifier = keccak256("nA1");
        aadhaar.completeAadhaarVerificationWithProof(
            user,
            new bytes(65),
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _mkSignals(keccak256("root")),
            nullifier
        );
        vm.expectRevert();
        aadhaar.completeAadhaarVerificationWithProof(
            user,
            new bytes(65),
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _mkSignals(keccak256("root")),
            nullifier
        );
        vm.stopPrank();
    }

    function test_completeAadhaarVerificationWithProof_invalid_root_reverts()
        public
    {
        vm.startPrank(user);
        aadhaar.requestAadhaarVerification(
            bytes32("ah"),
            bytes32("otp"),
            "OTP"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectRevert();
        aadhaar.completeAadhaarVerificationWithProof(
            user,
            new bytes(65),
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            _mkSignals(bytes32(uint256(0x1234))),
            keccak256("nA2")
        );
        vm.stopPrank();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {IncomeVerificationManager} from "src/verification/IncomeVerificationManager.sol";
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

contract IncomeVerificationManagerWithProofTest is Test {
    ZKProofManager zk;
    IncomeVerificationManager income;
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

        // Grant roles for registry + score
        registry.grantRole(registry.DEFAULT_ADMIN_ROLE(), admin);
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), admin);
        score.grantRole(score.DEFAULT_ADMIN_ROLE(), admin);
        score.grantRole(score.SCORE_MANAGER_ROLE(), address(registry));
        logger.grantRole(logger.DEFAULT_ADMIN_ROLE(), admin);

        // Grant logger permissions to registry and score
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        logger.grantRole(LOGGER_ROLE, address(registry));
        logger.grantRole(LOGGER_ROLE, address(score));
        // Managers log directly; grant them too
        // (after deployment below, but we can predeclare and grant after instantiation)

        // Deploy managers
        TestFaceManager face = new TestFaceManager();
        aadhaar = new AadhaarVerificationManager(
            address(logger),
            address(registry),
            address(score),
            address(face)
        );
        income = new IncomeVerificationManager(
            address(logger),
            address(registry),
            address(score),
            address(aadhaar)
        );
        logger.grantRole(LOGGER_ROLE, address(aadhaar));
        logger.grantRole(LOGGER_ROLE, address(income));
        // Grant needed roles to managers
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(aadhaar));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(income));
        score.grantRole(score.SCORE_MANAGER_ROLE(), address(aadhaar));
        score.grantRole(score.SCORE_MANAGER_ROLE(), address(income));

        // Register user
        registry.registerIdentity(user, bytes32("commit"));

        // Allow oracle roles
        aadhaar.grantRole(aadhaar.UIDAI_ORACLE_ROLE(), admin);
        income.grantRole(income.INCOME_ORACLE_ROLE(), admin);
        vm.stopPrank();

        // Prepare ZK manager and verifier
        vm.startPrank(admin);
        zk = new ZKProofManager();
        verifier = new TestGroth16Verifier();
        // Register types in order: 0 AGE_GTE, 1 ATTR_EQ, 2 INCOME_GTE, 3 AGE_LTE
        zk.addProofType("AGE_GTE", address(verifier));
        zk.addProofType("ATTR_EQ", address(verifier));
        zk.addProofType("INCOME_GTE", address(verifier));
        zk.addProofType("AGE_LTE", address(verifier));
        bytes32 root = keccak256("root");
        zk.anchorRoot(root);

        // Wire managers
        income.setZkProofManager(address(zk));
        aadhaar.setZkProofManager(address(zk));

        // Mark Aadhaar as verified via normal completion to satisfy precondition
        vm.stopPrank();
        vm.startPrank(user);
        aadhaar.requestAadhaarVerification(
            bytes32("ahash"),
            bytes32("otp"),
            "OTP"
        );
        vm.stopPrank();
        vm.startPrank(admin);
        aadhaar.completeAadhaarVerification(user, true, new bytes(65));
        vm.stopPrank();
    }

    function _mkSignals(bytes32 root) internal pure returns (uint256[] memory) {
        uint256[] memory sigs = new uint256[](2);
        sigs[0] = uint256(root);
        sigs[1] = 42; // threshold placeholder
        return sigs;
    }

    function test_completeIncomeVerificationWithProof_success() public {
        vm.startPrank(user);
        income.requestIncomeVerification(
            bytes32("ihash"),
            IncomeVerificationManager.IncomeRange.Lakh5to10,
            "ITR"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        bytes32 nullifier = keccak256("n1");
        uint256[] memory sigs = _mkSignals(keccak256("root"));
        income.completeIncomeVerificationWithProof(
            user,
            hex"01",
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
        vm.stopPrank();

        // Assert verified and trust score increased
        (
            IncomeVerificationManager.IncomeRange rng,
            ,
            bool isVerified,
            ,
            uint256 expiry,
            bool isExpired
        ) = income.getIncomeVerificationInfo(user);
        assertTrue(isVerified, "income verified");
        assertGt(expiry, 0, "expiry set");
        assertFalse(isExpired, "not expired");
        rng; // silence var-not-used
    }

    function test_completeIncomeVerificationWithProof_replay_nullifier_reverts()
        public
    {
        vm.startPrank(user);
        income.requestIncomeVerification(
            bytes32("ihash"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        bytes32 nullifier = keccak256("n1");
        uint256[] memory sigs = _mkSignals(keccak256("root"));
        income.completeIncomeVerificationWithProof(
            user,
            hex"01",
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
        // Second time should revert inside ZKProofManager
        vm.expectRevert();
        income.completeIncomeVerificationWithProof(
            user,
            hex"01",
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
        vm.stopPrank();
    }

    function test_completeIncomeVerificationWithProof_invalid_root_reverts()
        public
    {
        vm.startPrank(user);
        income.requestIncomeVerification(
            bytes32("ihash"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        bytes32 nullifier = keccak256("n2");
        uint256[] memory sigs = _mkSignals(bytes32(uint256(0x1234))); // not anchored
        vm.expectRevert();
        income.completeIncomeVerificationWithProof(
            user,
            hex"01",
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            sigs,
            nullifier
        );
        vm.stopPrank();
    }
}

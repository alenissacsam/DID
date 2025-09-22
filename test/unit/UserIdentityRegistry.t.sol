// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract UserIdentityRegistryTest is Test {
    UserIdentityRegistry reg;
    VerificationLogger logger;
    TrustScore trust;

    address manager = address(0xBEEF);
    address user = address(0xA11CE);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        reg = new UserIdentityRegistry(address(logger), address(trust));

        // grant roles (this test has DEFAULT_ADMIN_ROLE by constructor)
        reg.grantRole(reg.REGISTRY_MANAGER_ROLE(), manager);
        reg.grantRole(reg.PAUSER_ROLE(), manager);

        // allow contracts to log
        logger.grantRole(logger.LOGGER_ROLE(), address(reg));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        // allow registry to initialize TrustScore
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(reg));
    }

    function test_register_and_getInfo() public {
        vm.prank(manager);
        reg.registerIdentity(user, bytes32("commit"));

        assertTrue(reg.isRegistered(user));
        (bool face, bool aadhaar, bool income, uint256 level) = reg
            .getVerificationStatus(user);
        assertFalse(face);
        assertFalse(aadhaar);
        assertFalse(income);
        assertEq(level, 0);
        assertEq(reg.getIdentityCommitment(user), bytes32("commit"));
    }

    function test_update_verification_status_and_level() public {
        vm.startPrank(manager);
        reg.registerIdentity(user, bytes32("c1"));
        reg.updateVerificationStatus(
            user,
            UserIdentityRegistry.VerificationKind.Face,
            true
        );
        (, , , uint256 level1) = reg.getVerificationStatus(user);
        assertEq(level1, 1);
        reg.updateVerificationStatus(
            user,
            UserIdentityRegistry.VerificationKind.Aadhaar,
            true
        );
        (, , , uint256 level2) = reg.getVerificationStatus(user);
        assertEq(level2, 2);
        reg.updateVerificationStatus(
            user,
            UserIdentityRegistry.VerificationKind.Income,
            true
        );
        (, , , uint256 level3) = reg.getVerificationStatus(user);
        assertEq(level3, 3);
        vm.stopPrank();
    }

    function test_lock_unlock_identity() public {
        vm.prank(manager);
        reg.registerIdentity(user, bytes32("c1"));

        vm.prank(manager);
        reg.lockIdentity(user, 1 days);
        assertTrue(reg.isIdentityLocked(user));

        vm.prank(manager);
        reg.unlockIdentity(user);
        assertFalse(reg.isIdentityLocked(user));
    }

    function test_set_metadata_uri() public {
        vm.prank(manager);
        reg.registerIdentity(user, bytes32("c1"));
        vm.prank(manager);
        reg.setMetadataURI(user, "ipfs://cid");
        UserIdentityRegistry.Identity memory id = reg.getIdentityInfo(user);
        assertEq(id.metadataURI, "ipfs://cid");
    }

    function test_update_commitment_marks_old_inactive() public {
        vm.startPrank(manager);
        reg.registerIdentity(user, bytes32("old"));
        reg.updateIdentityCommitment(user, bytes32("new"));
        vm.stopPrank();

        assertTrue(reg.isCommitmentActive(bytes32("new")));
        assertFalse(reg.isCommitmentActive(bytes32("old")));
    }
}

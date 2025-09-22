// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract UserIdentityRegistryFuzzTest is Test {
    VerificationLogger logger;
    TrustScore trust;
    UserIdentityRegistry reg;
    address admin = address(0xAB);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        reg = new UserIdentityRegistry(address(logger), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(reg));
        reg.grantRole(reg.REGISTRY_MANAGER_ROLE(), admin);
        // Also grant manager role to this test so we can call without prank when needed
        reg.grantRole(reg.REGISTRY_MANAGER_ROLE(), address(this));
        logger.grantRole(logger.LOGGER_ROLE(), address(reg));
    }

    function testFuzz_register_update_lock(
        address user,
        bytes32 c1,
        bytes32 c2,
        string memory uri,
        uint256 lockSecs
    ) public {
        vm.assume(user != address(0));
        vm.assume(c1 != bytes32(0) && c2 != bytes32(0) && c2 != c1);
        vm.assume(bytes(uri).length > 0);
        lockSecs = lockSecs % 30 days;

        vm.prank(admin);
        reg.registerIdentity(user, c1);
        assertTrue(reg.isRegistered(user));

        vm.prank(admin);
        reg.setMetadataURI(user, uri);

        vm.prank(admin);
        reg.updateIdentityCommitment(user, c2);

        vm.prank(admin);
        reg.lockIdentity(user, lockSecs);
        assertTrue(reg.isIdentityLocked(user));

        vm.warp(block.timestamp + lockSecs + 1);
        // Auto-unlock check via with-update call
        bool locked = reg.isIdentityLockedWithUpdate(user);
        assertFalse(locked);
    }
}

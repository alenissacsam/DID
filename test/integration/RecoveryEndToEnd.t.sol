// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {GuardianManager} from "src/advanced_features/GuardianManager.sol";
import {RecoveryManager} from "src/advanced_features/RecoveryManager.sol";

contract RecoveryEndToEndTest is Test {
    VerificationLogger logger;
    UserIdentityRegistry registry;
    TrustScore trust;
    GuardianManager guardians;
    RecoveryManager recovery;

    address admin = address(0xAA);
    address user = address(0xBB);
    address g1 = address(0xC1);
    address g2 = address(0xC2);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        guardians = new GuardianManager(
            address(logger),
            address(registry),
            address(trust)
        );
        recovery = new RecoveryManager(address(logger), address(guardians));

        // allow to log
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(guardians));
        logger.grantRole(logger.LOGGER_ROLE(), address(recovery));

        // registry needs to init trust on register
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));
        // GuardianManager will call registry.unlockIdentity in executeRecovery; grant manager role
        vm.prank(admin);
        registry.grantRole(
            registry.REGISTRY_MANAGER_ROLE(),
            address(guardians)
        );
        // GuardianManager will call trust.unlockScore; grant score manager role
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(guardians));

        // Set up identities and trust for guardians
        vm.prank(admin);
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), admin);
        vm.prank(admin);
        registry.registerIdentity(user, bytes32("u1"));
        vm.prank(admin);
        registry.registerIdentity(g1, bytes32("g1"));
        vm.prank(admin);
        registry.registerIdentity(g2, bytes32("g2"));

        // Boost guardians' trust to pass GuardianManager checks
        vm.prank(address(registry));
        trust.updateScore(g1, 100, "Participation");
        vm.prank(address(registry));
        trust.updateScore(g2, 100, "Participation");

        // Setup guardian set with threshold 2
        address[] memory gs = new address[](2);
        gs[0] = g1;
        gs[1] = g2;
        string[] memory rel = new string[](2);
        rel[0] = "friend";
        rel[1] = "family";

        vm.prank(user);
        guardians.setupGuardianSet(gs, rel, 2);
    }

    function test_end_to_end_recovery_flow() public {
        // User gets locked somewhere (simulate via registry lock and trust lock)
        vm.prank(admin);
        registry.lockIdentity(user, 1 days);
        // Also lock the trust score to mirror real recovery scenarios
        vm.prank(address(registry));
        trust.lockScore(user, "recovery");

        // Guardian 1 proposes recovery
        vm.warp(block.timestamp + 1);
        vm.prank(g1);
        bytes32 recId = guardians.proposeRecovery(
            user,
            address(0x1111),
            keccak256("data"),
            "lost key"
        );

        // Guardian 2 votes
        vm.prank(g2);
        guardians.voteForRecovery(recId);

        // Wait for execution delay
        vm.warp(block.timestamp + 48 hours);

        // Execute recovery: should unlock identity and trust
        guardians.executeRecovery(recId);

        // Verify effects: identity should be unlocked
        bool locked = registry.isIdentityLocked(user);
        assertFalse(locked);
    }
}

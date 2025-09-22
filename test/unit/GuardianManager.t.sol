// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {GuardianManager} from "../../src/advanced_features/GuardianManager.sol";

contract GuardianManagerTest is Test {
    VerificationLogger logger;
    UserIdentityRegistry registry;
    TrustScore trust;
    GuardianManager gm;

    address user = address(0x123);
    address g1 = address(0x1001);
    address g2 = address(0x1002);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        gm = new GuardianManager(
            address(logger),
            address(registry),
            address(trust)
        );

        // Roles: allow GuardianManager and TrustScore to log; allow this test to manage registry & score
        logger.grantRole(logger.LOGGER_ROLE(), address(gm));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), address(this));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(this));
        // Let registry initialize trust via registerIdentity
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));

        // Initialize trust for guardians (user will be initialized via registry)
        trust.initializeUser(g1);
        trust.initializeUser(g2);

        // Set trust high for guardians
        trust.updateScore(g1, 100, "guardian");
        trust.updateScore(g2, 100, "guardian");

        // Register identity for user (required by GuardianManager); also initializes trust for user
        registry.registerIdentity(user, keccak256("ic"));
    }

    function test_setup_and_update_threshold() public {
        address[] memory guardians = new address[](2);
        guardians[0] = g1;
        guardians[1] = g2;
        string[] memory rel = new string[](2);
        rel[0] = "friend";
        rel[1] = "family";

        vm.prank(user);
        gm.setupGuardianSet(guardians, rel, 1);

        (address[] memory list, uint256 threshold, bool isSetup) = gm
            .getGuardianSet(user);
        assertEq(list.length, 2);
        assertEq(threshold, 1);
        assertTrue(isSetup);

        vm.prank(user);
        gm.updateThreshold(2);
        (, uint256 newThr, ) = gm.getGuardianSet(user);
        assertEq(newThr, 2);
    }
}

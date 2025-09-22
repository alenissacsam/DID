// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";
import {GuardianManager} from "src/advanced_features/GuardianManager.sol";

contract GuardianManagerFuzzTest is Test {
    VerificationLogger logger;
    TrustScore trust;
    UserIdentityRegistry reg;
    GuardianManager gm;

    address user = address(0xAAA1);
    address g1 = address(0xA1);
    address g2 = address(0xA2);
    address admin = address(0xAD);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        reg = new UserIdentityRegistry(address(logger), address(trust));
        gm = new GuardianManager(address(logger), address(reg), address(trust));

        // Allow logging from contracts that emit events
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        logger.grantRole(logger.LOGGER_ROLE(), address(reg));
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(reg));
        logger.grantRole(logger.LOGGER_ROLE(), address(gm));

        vm.prank(admin);
        reg.grantRole(reg.REGISTRY_MANAGER_ROLE(), admin);
        vm.prank(admin);
        reg.registerIdentity(user, bytes32("u"));
        vm.prank(admin);
        reg.registerIdentity(g1, bytes32("g1"));
        vm.prank(admin);
        reg.registerIdentity(g2, bytes32("g2"));
        vm.prank(address(reg));
        trust.updateScore(g1, 100, "Participation");
        vm.prank(address(reg));
        trust.updateScore(g2, 100, "Participation");

        // baseline guardian set
        address[] memory gs = new address[](2);
        gs[0] = g1;
        gs[1] = g2;
        string[] memory rel = new string[](2);
        rel[0] = "f";
        rel[1] = "f2";
        vm.prank(user);
        gm.setupGuardianSet(gs, rel, 2);
    }

    function testFuzz_propose_and_execute_change(address newG) public {
        vm.assume(
            newG != address(0) && newG != user && newG != g1 && newG != g2
        );
        // Ensure new guardian has identity and trust via authorized admin
        vm.prank(admin);
        reg.registerIdentity(newG, keccak256(abi.encodePacked(newG)));
        vm.prank(address(reg));
        trust.updateScore(newG, 100, "Participation");

        vm.prank(user);
        bytes32 changeId = gm.proposeGuardianChange(newG, "rel", true, "add");
        // wait addition delay
        (, , bool isSetup) = gm.getGuardianSet(user);
        assertTrue(isSetup);
        vm.warp(block.timestamp + gm.DEFAULT_GUARDIAN_DELAY());
        vm.prank(user);
        gm.executeGuardianChange(changeId);

        // Now propose removal and execute
        vm.prank(user);
        bytes32 remId = gm.proposeGuardianChange(g1, "", false, "rm");
        vm.warp(block.timestamp + gm.DEFAULT_GUARDIAN_DELAY());
        vm.prank(user);
        gm.executeGuardianChange(remId);
    }
}

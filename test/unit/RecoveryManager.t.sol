// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {RecoveryManager} from "../../src/advanced_features/RecoveryManager.sol";
import {IGuardianManager} from "../../src/interfaces/IGuardianManager.sol";

contract GuardianManagerStub is IGuardianManager {
    mapping(address => mapping(address => bool)) public isG;

    function isGuardian(
        address user,
        address guardian
    ) external view returns (bool) {
        return isG[user][guardian];
    }

    function getGuardianSet(
        address
    ) external pure returns (address[] memory, uint256, bool) {
        address[] memory a;
        return (a, 1, true);
    }

    function set(address user, address guardian, bool v) external {
        isG[user][guardian] = v;
    }
}

contract RecoveryManagerTest is Test {
    VerificationLogger logger;
    GuardianManagerStub gms;
    RecoveryManager rm;

    address owner = address(0xA1);
    address guardian = address(0xB2);
    address wallet = address(0xC3);
    address newOwner = address(0xD4);

    function setUp() public {
        logger = new VerificationLogger();
        gms = new GuardianManagerStub();
        rm = new RecoveryManager(address(logger), address(gms));
        logger.grantRole(logger.LOGGER_ROLE(), address(rm));
        gms.set(owner, guardian, true);
    }

    function test_request_confirm_execute() public {
        uint256 id = rm.requestRecovery(
            wallet,
            newOwner,
            "lost",
            0,
            owner,
            guardian
        );
        assertEq(id, 1);
        // Do not confirm again with the same guardian; the initial requester is already counted.
        address ret = rm.executeRecovery(id, wallet, owner);
        assertEq(ret, newOwner);
    }
}

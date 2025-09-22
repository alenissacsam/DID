// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {RecoveryManager} from "src/advanced_features/RecoveryManager.sol";
import {IGuardianManager} from "src/interfaces/IGuardianManager.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";

contract StubGuardianManager is IGuardianManager {
    mapping(address => mapping(address => bool)) public isG;
    mapping(address => uint256) public thresholds;

    function setGuardian(address owner, address g, bool active) external {
        isG[owner][g] = active;
    }

    function setThreshold(address owner, uint256 t) external {
        thresholds[owner] = t;
    }

    function isGuardian(
        address owner,
        address guardian
    ) external view returns (bool) {
        return isG[owner][guardian];
    }

    function getGuardianSet(
        address owner
    ) external view returns (address[] memory, uint256 threshold, bool) {
        address[] memory empty;
        return (empty, thresholds[owner], true);
    }
}

contract RecoveryManagerFuzzTest is Test {
    VerificationLogger logger;
    StubGuardianManager stub;
    RecoveryManager rm;

    address owner = address(0x11);
    address guardian1 = address(0x21);
    address guardian2 = address(0x22);

    function setUp() public {
        logger = new VerificationLogger();
        stub = new StubGuardianManager();
        rm = new RecoveryManager(address(logger), address(stub));
        stub.setGuardian(owner, guardian1, true);
        stub.setGuardian(owner, guardian2, true);
        stub.setThreshold(owner, 2);
    }

    function testFuzz_recovery_flow(
        address wallet,
        address newOwner,
        uint32 delay
    ) public {
        vm.assume(wallet != address(0) && newOwner != address(0));
        delay = delay % 7 days;
        uint256 rid = rm.requestRecovery(
            wallet,
            newOwner,
            "lost",
            delay,
            owner,
            guardian1
        );
        // confirm by second guardian
        rm.confirmRecovery(rid, wallet, owner, guardian2);
        // wait for delay
        vm.warp(block.timestamp + delay + 1);
        address result = rm.executeRecovery(rid, wallet, owner);
        assertEq(result, newOwner);
    }
}

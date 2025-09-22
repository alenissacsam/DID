// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";

contract VerificationLoggerTest is Test {
    VerificationLogger logger;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        logger = new VerificationLogger();
        // grant LOGGER_ROLE to this test contract using default admin (this test has it by constructor)
        bytes32 role = logger.LOGGER_ROLE();
        logger.grantRole(role, address(this));
    }

    function test_logEvent_emitsAndStores() public {
        logger.logEvent("TEST", alice, keccak256("x"));
        assertEq(logger.getTotalLogs(), 1);

        uint256[] memory ids = logger.getUserLogs(alice);
        assertEq(ids.length, 1);

        (uint256 total, uint256 archived, uint256 active) = logger
            .getLogStats();
        assertEq(total, 1);
        assertEq(archived, 0);
        assertEq(active, 1);
    }

    function test_batchLogEvents() public {
        string[] memory typesArr = new string[](2);
        address[] memory usersArr = new address[](2);
        bytes32[] memory dataArr = new bytes32[](2);
        typesArr[0] = "A";
        typesArr[1] = "B";
        usersArr[0] = alice;
        usersArr[1] = bob;
        dataArr[0] = keccak256("1");
        dataArr[1] = keccak256("2");

        logger.batchLogEvents(typesArr, usersArr, dataArr);
        assertEq(logger.getTotalLogs(), 2);

        uint256[] memory aLogs = logger.getUserLogs(alice);
        uint256[] memory bLogs = logger.getUserLogs(bob);
        assertEq(aLogs.length, 1);
        assertEq(bLogs.length, 1);
    }

    function test_archiveLogs_marksArchived() public {
        for (uint i = 0; i < 3; i++) {
            logger.logEvent("T", alice, bytes32(uint256(i + 1)));
        }
        assertEq(logger.getTotalLogs(), 3);
        // Allow archiving by setting threshold low (this test has DEFAULT_ADMIN_ROLE)
        logger.setArchiveThreshold(0);
        logger.archiveLogs(1, 2);

        (, uint256 archived, uint256 active) = logger.getLogStats();
        assertEq(archived, 2);
        assertEq(active, 1);
    }
}

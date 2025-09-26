// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {OrganizationLogic} from "../../src/organizations/OrganizationLogic.sol";
import {OrganizationStorage} from "../../src/organizations/OrganizationStorage.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";
import {ICertificateManager} from "../../src/interfaces/ICertificateManager.sol";
import {ITrustScore} from "../../src/interfaces/ITrustScore.sol";

contract DummyLoggerOrg is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

contract DummyCertMgr is ICertificateManager {
    function getCertificatesByHolder(
        address
    ) external pure returns (uint256[] memory arr) {
        return arr;
    }

    function verifyCertificate(uint256) external pure returns (bool) {
        return true;
    }

    function grantRole(bytes32, address) external {}

    function revokeRole(bytes32, address) external {}
}

contract DummyTrust is ITrustScore {
    function getTrustScore(address) external pure returns (uint256) {
        return 0;
    }

    function updateScoreForGaslessTransaction(address) external {}

    function initializeUser(address) external {}

    function updateScore(address, int256, string memory) external {}

    function unlockScore(address) external {}
}

contract OrgHarness is OrganizationLogic {
    constructor(
        address cert,
        address trust,
        address logger
    ) OrganizationLogic(cert, trust, logger) {}
}

contract OrganizationLogic_Branches is Test {
    OrgHarness org;
    DummyLoggerOrg logger;
    DummyCertMgr cert;
    DummyTrust trust;

    function setUp() public {
        logger = new DummyLoggerOrg();
        cert = new DummyCertMgr();
        trust = new DummyTrust();
        org = new OrgHarness(address(cert), address(trust), address(logger));
    }

    function test_register_duplicate_reverts() public {
        org.registerOrganization(
            address(0xAA01),
            "OrgA",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG1",
            "site",
            "email@example.com",
            "meta",
            bytes32(uint256(1))
        );
        vm.expectRevert(bytes("Already registered"));
        org.registerOrganization(
            address(0xAA01),
            "OrgA",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG1",
            "site",
            "email@example.com",
            "meta",
            bytes32(uint256(1))
        );
    }
}

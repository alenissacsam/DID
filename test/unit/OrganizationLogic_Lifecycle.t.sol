// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {OrganizationLogic} from "../../src/organizations/OrganizationLogic.sol";
import {OrganizationStorage} from "../../src/organizations/OrganizationStorage.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";
import {ICertificateManager} from "../../src/interfaces/ICertificateManager.sol";
import {ITrustScore} from "../../src/interfaces/ITrustScore.sol";

// Simple mocks
contract OrgLogger is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

contract OrgCert is ICertificateManager {
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

contract OrgTrust is ITrustScore {
    mapping(address => uint256) public score;

    function getTrustScore(address user) external view returns (uint256) {
        return score[user];
    }

    function updateScoreForGaslessTransaction(address user) external {
        score[user] += 1;
    }

    function initializeUser(address user) external {
        if (score[user] == 0) score[user] = 1;
    }

    function updateScore(address user, int256 delta, string memory) external {
        if (delta >= 0) score[user] += uint256(delta);
        else score[user] -= uint256(-delta);
    }

    function unlockScore(address) external {}
}

contract OrgFullHarness is OrganizationLogic {
    constructor(
        address cert,
        address trust,
        address logger
    ) OrganizationLogic(cert, trust, logger) {}
}

contract OrganizationLogic_Lifecycle is Test {
    OrgFullHarness org;
    OrgLogger logger;
    OrgCert cert;
    OrgTrust trust;
    address admin = address(this);
    address orgAddr = address(0xABCD1);

    function setUp() public {
        logger = new OrgLogger();
        cert = new OrgCert();
        trust = new OrgTrust();
        org = new OrgFullHarness(
            address(cert),
            address(trust),
            address(logger)
        );
    }

    function _registerBasic() internal {
        org.registerOrganization(
            orgAddr,
            "OrgOne",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG-001",
            "site",
            "mail@ex.com",
            "meta1",
            bytes32(uint256(11))
        );
    }

    function test_full_lifecycle_and_accreditations() public {
        // Register
        _registerBasic();
        // Approve
        org.approveOrganization(orgAddr);
        // Grant issuer role (trustScore updated inside approve to MIN_ORG_TRUST_SCORE)
        org.grantIssuerRole(orgAddr);
        // Add accreditation (International)
        org.addAccreditation(
            orgAddr,
            OrganizationStorage.AccreditationType.International
        );
        // Suspend organization
        org.suspendOrganization(orgAddr, "risk");
        // Reactivate
        org.reactivateOrganization(orgAddr);
        // Re-grant issuer (was implicitly removed on suspend) then revoke
        org.grantIssuerRole(orgAddr);
        org.revokeIssuerRole(orgAddr, "cleanup");
        // Revoke accreditation
        org.revokeAccreditation(
            orgAddr,
            OrganizationStorage.AccreditationType.International
        );
        // Update info
        vm.prank(orgAddr);
        org.updateOrganizationInfo("site2", "mail2@ex.com", "meta2");
    }

    function test_register_duplicate_name_and_kyc_reverts() public {
        _registerBasic();
        // duplicate orgAddress
        vm.expectRevert(bytes("Already registered"));
        org.registerOrganization(
            orgAddr,
            "OrgOne",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG-002",
            "site",
            "mail@ex.com",
            "meta1",
            bytes32(uint256(12))
        );
        // duplicate registration number
        vm.expectRevert(bytes("Reg num used"));
        org.registerOrganization(
            address(0xABCD2),
            "OrgTwo",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG-001",
            "site",
            "mail@ex.com",
            "meta1",
            bytes32(uint256(13))
        );
        // duplicate name
        vm.expectRevert(bytes("Name used"));
        org.registerOrganization(
            address(0xABCD3),
            "OrgOne",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG-003",
            "site",
            "mail@ex.com",
            "meta1",
            bytes32(uint256(14))
        );
        // duplicate kyc hash
        vm.expectRevert(bytes("KYC used"));
        org.registerOrganization(
            address(0xABCD4),
            "OrgFour",
            OrganizationStorage.OrganizationType(0),
            "IN",
            "KA",
            "BLR",
            "REG-004",
            "site",
            "mail@ex.com",
            "meta1",
            bytes32(uint256(11))
        );
    }

    function test_grantIssuerRole_low_trust_reverts() public {
        _registerBasic();
        // Not yet approved => status Pending -> cannot grant issuer (requires Active and trust score >= MIN_ORG_TRUST_SCORE)
        vm.expectRevert(bytes("Not active"));
        org.grantIssuerRole(orgAddr);
        // Approve sets trustScore to MIN_ORG_TRUST_SCORE
        org.approveOrganization(orgAddr);
        // Revoke issuer before set (should succeed first grant then revert second)
        org.grantIssuerRole(orgAddr);
        vm.expectRevert(bytes("Already issuer"));
        org.grantIssuerRole(orgAddr);
    }

    function test_revokeIssuerRole_not_issuer_reverts() public {
        _registerBasic();
        org.approveOrganization(orgAddr);
        vm.expectRevert(bytes("Not issuer"));
        org.revokeIssuerRole(orgAddr, "none");
    }

    function test_updateCertificateStats_issue_and_revoke_paths() public {
        _registerBasic();
        org.approveOrganization(orgAddr);
        // simulate certificate manager calls (since msg.sender must be certificateManager)
        vm.prank(address(cert));
        org.updateCertificateStats(orgAddr, false); // issue
        vm.prank(address(cert));
        org.updateCertificateStats(orgAddr, true); // revoke
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./OrganizationStorage.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/ITrustScore.sol";
import "../interfaces/IVerificationLogger.sol";

interface ICertificateManager {
    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;
}

abstract contract OrganizationLogic is
    OrganizationStorage,
    AccessControl,
    ReentrancyGuard
{
    bytes32 public constant ORG_ADMIN_ROLE = keccak256("ORG_ADMIN_ROLE");
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    ICertificateManager public certificateManager;
    ITrustScore public trustScore;
    IVerificationLogger public verificationLogger;
    uint256 public constant MIN_ORG_TRUST_SCORE = 25;

    event OrganizationRegistered(
        address indexed orgAddress,
        string name,
        OrganizationType orgType
    );
    event OrganizationApproved(address indexed orgAddress, string name);
    event OrganizationSuspended(address indexed orgAddress, string reason);
    event OrganizationReactivated(address indexed orgAddress);
    event IssuerRoleGranted(address indexed orgAddress, string name);
    event IssuerRoleRevoked(address indexed orgAddress, string reason);
    event AccreditationAdded(
        address indexed orgAddress,
        AccreditationType accType
    );
    event AccreditationRevoked(
        address indexed orgAddress,
        AccreditationType accType
    );
    event OrganizationUpdated(address indexed orgAddress, string updateType);

    constructor(
        address _certificateManager,
        address _trustScore,
        address _verificationLogger
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORG_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        certificateManager = ICertificateManager(_certificateManager);
        trustScore = ITrustScore(_trustScore);
        verificationLogger = IVerificationLogger(_verificationLogger);
    }

    function registerOrganization(
        address orgAddress,
        string memory name,
        OrganizationType orgType,
        string memory country,
        string memory state,
        string memory city,
        string memory registrationNumber,
        string memory website,
        string memory email,
        string memory metadataUri,
        bytes32 kycHash
    ) public nonReentrant onlyRole(ORG_ADMIN_ROLE) {
        require(orgAddress != address(0), "Invalid org address");
        require(
            bytes(name).length > 0 && bytes(name).length <= 100,
            "Invalid name length"
        );
        require(
            bytes(registrationNumber).length > 0 &&
                bytes(registrationNumber).length <= 50,
            "Invalid reg num length"
        );
        require(
            bytes(country).length > 0 && bytes(country).length <= 50,
            "Invalid country"
        );
        require(bytes(email).length > 0, "Email required");
        require(kycHash != bytes32(0), "Invalid KYC hash");
        require(
            organizations[orgAddress].orgAddress == address(0),
            "Already registered"
        );
        require(
            registrationToAddress[registrationNumber] == address(0),
            "Reg num used"
        );
        require(nameToAddress[name] == address(0), "Name used");
        require(!usedKycHashes[kycHash], "KYC used");

        Organization storage org = organizations[orgAddress];
        org.orgAddress = orgAddress;
        org.name = name;
        org.orgType = orgType;
        org.status = OrganizationStatus.Pending;
        org.country = country;
        org.state = state;
        org.city = city;
        org.registrationNumber = registrationNumber;
        org.website = website;
        org.email = email;
        org.metadataUri = metadataUri;
        org.registeredAt = block.timestamp;
        org.lastUpdated = block.timestamp;
        org.canIssueCertificates = false;
        org.kycHash = kycHash;
        org.trustScore = 0;
        org.certificatesIssued = 0;
        org.certificatesRevoked = 0;
        delete org.accreditations;

        registrationToAddress[registrationNumber] = orgAddress;
        nameToAddress[name] = orgAddress;
        usedKycHashes[kycHash] = true;
        allOrganizations.push(orgAddress);
        pendingOrganizations.push(orgAddress);

        totalOrganizations++;
        pendingOrgCount++;

        if (address(verificationLogger) != address(0)) {
            verificationLogger.logEvent(
                "ORGANIZATION_REGISTERED",
                orgAddress,
                keccak256(abi.encodePacked(name, registrationNumber))
            );
        }

        emit OrganizationRegistered(orgAddress, name, orgType);
    }

    function approveOrganization(
        address orgAddress
    ) public onlyRole(VERIFIER_ROLE) {
        require(orgAddress != address(0), "Invalid address");
        Organization storage org = organizations[orgAddress];
        require(org.orgAddress != address(0), "Not found");
        require(org.status == OrganizationStatus.Pending, "Not pending");

        org.status = OrganizationStatus.Active;
        org.lastUpdated = block.timestamp;
        org.trustScore = MIN_ORG_TRUST_SCORE;

        _removeFromArray(pendingOrganizations, orgAddress);
        activeOrganizations.push(orgAddress);
        activeOrgCount++;

        // Prevent underflow
        if (pendingOrgCount > 0) {
            pendingOrgCount--;
        }

        if (address(trustScore) != address(0)) {
            trustScore.updateScore(
                orgAddress,
                int256(MIN_ORG_TRUST_SCORE),
                "Approved"
            );
        }

        if (address(verificationLogger) != address(0)) {
            verificationLogger.logEvent(
                "ORGANIZATION_APPROVED",
                orgAddress,
                keccak256(abi.encodePacked(org.name))
            );
        }

        emit OrganizationApproved(orgAddress, org.name);
    }

    function grantIssuerRole(
        address orgAddress
    ) public onlyRole(ORG_ADMIN_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.status == OrganizationStatus.Active, "Not active");
        require(!org.canIssueCertificates, "Already issuer");
        require(org.trustScore >= MIN_ORG_TRUST_SCORE, "Low trust");
        org.canIssueCertificates = true;
        org.lastUpdated = block.timestamp;
        certificateManager.grantRole(ISSUER_ROLE, orgAddress);
        trustScore.updateScore(orgAddress, 25, "Granted issuer");
        emit IssuerRoleGranted(orgAddress, org.name);
    }

    function revokeIssuerRole(
        address orgAddress,
        string memory reason
    ) public onlyRole(ORG_ADMIN_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.canIssueCertificates, "Not issuer");
        org.canIssueCertificates = false;
        org.lastUpdated = block.timestamp;
        certificateManager.revokeRole(ISSUER_ROLE, orgAddress);
        trustScore.updateScore(orgAddress, -25, "Revoked issuer");
        emit IssuerRoleRevoked(orgAddress, reason);
    }

    function suspendOrganization(
        address orgAddress,
        string memory reason
    ) public onlyRole(VERIFIER_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.status == OrganizationStatus.Active, "Not active");
        org.status = OrganizationStatus.Suspended;
        org.lastUpdated = block.timestamp;
        if (org.canIssueCertificates) {
            org.canIssueCertificates = false;
            certificateManager.revokeRole(ISSUER_ROLE, orgAddress);
        }
        _removeFromArray(activeOrganizations, orgAddress);
        activeOrgCount--;
        suspendedOrgCount++;
        trustScore.updateScore(orgAddress, -50, "Suspended");
        emit OrganizationSuspended(orgAddress, reason);
    }

    function reactivateOrganization(
        address orgAddress
    ) public onlyRole(VERIFIER_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.status == OrganizationStatus.Suspended, "Not suspended");
        org.status = OrganizationStatus.Active;
        org.lastUpdated = block.timestamp;
        activeOrganizations.push(orgAddress);
        activeOrgCount++;
        suspendedOrgCount--;
        trustScore.updateScore(orgAddress, 25, "Reactivated");
        emit OrganizationReactivated(orgAddress);
    }

    function addAccreditation(
        address orgAddress,
        AccreditationType val
    ) public onlyRole(VERIFIER_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.orgAddress != address(0), "Not found");
        org.accreditations.push(val);
        org.lastUpdated = block.timestamp;
        int256 score = _getAccreditationScore(val);
        trustScore.updateScore(orgAddress, score, "Accreditation added");
        emit AccreditationAdded(orgAddress, val);
    }

    function revokeAccreditation(
        address orgAddress,
        AccreditationType val
    ) public onlyRole(VERIFIER_ROLE) {
        Organization storage org = organizations[orgAddress];
        require(org.orgAddress != address(0), "Not found");
        _removeAccreditation(org, val);
        org.lastUpdated = block.timestamp;
        int256 score = -_getAccreditationScore(val);
        trustScore.updateScore(orgAddress, score, "Accreditation revoked");
        emit AccreditationRevoked(orgAddress, val);
    }

    function updateOrganizationInfo(
        string memory website,
        string memory email,
        string memory metadataUri
    ) public {
        Organization storage org = organizations[msg.sender];
        require(org.orgAddress != address(0), "Not registered");
        org.website = website;
        org.email = email;
        org.metadataUri = metadataUri;
        org.lastUpdated = block.timestamp;
        emit OrganizationUpdated(msg.sender, "info");
    }

    function updateCertificateStats(
        address orgAddress,
        bool isRevocation
    ) public {
        require(msg.sender == address(certificateManager), "Not cert manager");
        Organization storage org = organizations[orgAddress];
        require(org.orgAddress != address(0), "Not found");
        if (isRevocation) {
            org.certificatesRevoked++;
            trustScore.updateScore(orgAddress, -2, "Cert revoked");
        } else {
            org.certificatesIssued++;
            trustScore.updateScore(orgAddress, 1, "Cert issued");
        }
        org.lastUpdated = block.timestamp;
    }

    function _removeFromArray(address[] storage arr, address target) internal {
        require(arr.length > 0, "Array is empty");
        uint256 len = arr.length;
        bool found = false;

        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == target) {
                // Move the last element to this position and remove the last element
                arr[i] = arr[len - 1];
                arr.pop();
                found = true;
                break;
            }
        }

        require(found, "Target not found in array");
    }

    function _removeAccreditation(
        Organization storage org,
        AccreditationType val
    ) internal {
        uint256 len = org.accreditations.length;
        for (uint256 i = 0; i < len; i++) {
            if (org.accreditations[i] == val) {
                org.accreditations[i] = org.accreditations[len - 1];
                org.accreditations.pop();
                break;
            }
        }
    }

    function _getAccreditationScore(
        AccreditationType accType
    ) private pure returns (int256) {
        if (accType == AccreditationType.International) return 50;
        if (accType == AccreditationType.National) return 40;
        if (accType == AccreditationType.Government) return 35;
        if (accType == AccreditationType.Professional) return 30;
        if (accType == AccreditationType.Regional) return 25;
        if (accType == AccreditationType.Internal) return 15;
        return 20;
    }
}

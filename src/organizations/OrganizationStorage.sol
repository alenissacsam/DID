// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

abstract contract OrganizationStorage {
    enum OrganizationType {
        University,
        College,
        School,
        TrainingInstitute,
        CertificationBody,
        GovernmentEntity,
        CorporateTraining,
        OnlinePlatform
    }
    enum OrganizationStatus {
        Pending,
        Active,
        Suspended,
        Deactivated,
        UnderReview
    }
    enum AccreditationType {
        National,
        Regional,
        International,
        Professional,
        Government,
        Internal
    }

    struct Organization {
        address orgAddress;
        string name;
        OrganizationType orgType;
        OrganizationStatus status;
        string country;
        string state;
        string city;
        string registrationNumber;
        string website;
        string email;
        string metadataUri;
        uint256 registeredAt;
        uint256 lastUpdated;
        bool canIssueCertificates;
        bytes32 kycHash;
        uint256 trustScore;
        uint256 certificatesIssued;
        uint256 certificatesRevoked;
        AccreditationType[] accreditations;
    }

    mapping(address => Organization) internal organizations;
    mapping(string => address) public registrationToAddress;
    mapping(string => address) public nameToAddress;
    mapping(bytes32 => bool) public usedKycHashes;

    address[] public allOrganizations;
    address[] public activeOrganizations;
    address[] public pendingOrganizations;

    uint256 public totalOrganizations;
    uint256 public activeOrgCount;
    uint256 public pendingOrgCount;
    uint256 public suspendedOrgCount;
}

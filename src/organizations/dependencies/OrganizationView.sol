// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../OrganizationStorage.sol";

contract OrganizationView is OrganizationStorage {
    function getActiveOrganizations() external view returns (address[] memory) {
        return activeOrganizations;
    }

    function getPendingOrganizations() external view returns (address[] memory) {
        return pendingOrganizations;
    }

    function getOrganizationsByType(OrganizationType orgType) external view returns (address[] memory) {
        uint256 orgCount = allOrganizations.length;
        uint256 count = 0;

        // First pass: count matching organizations
        unchecked {
            for (uint256 i = 0; i < orgCount; ++i) {
                if (organizations[allOrganizations[i]].orgType == orgType) {
                    ++count;
                }
            }
        }

        // Second pass: collect matching organizations
        address[] memory result = new address[](count);
        uint256 idx = 0;

        unchecked {
            for (uint256 i = 0; i < orgCount; ++i) {
                if (organizations[allOrganizations[i]].orgType == orgType) {
                    result[idx++] = allOrganizations[i];
                }
            }
        }

        return result;
    }

    function getOrganizationsByCountry(string memory country) external view returns (address[] memory) {
        bytes32 countryHash = keccak256(bytes(country));
        uint256 orgCount = allOrganizations.length;
        uint256 count = 0;

        // First pass: count matching organizations
        unchecked {
            for (uint256 i = 0; i < orgCount; ++i) {
                if (keccak256(bytes(organizations[allOrganizations[i]].country)) == countryHash) {
                    ++count;
                }
            }
        }

        // Second pass: collect matching organizations
        address[] memory result = new address[](count);
        uint256 idx = 0;

        unchecked {
            for (uint256 i = 0; i < orgCount; ++i) {
                if (keccak256(bytes(organizations[allOrganizations[i]].country)) == countryHash) {
                    result[idx++] = allOrganizations[i];
                }
            }
        }

        return result;
    }

    function getGlobalStats() external view returns (uint256, uint256, uint256, uint256) {
        return (totalOrganizations, activeOrgCount, pendingOrgCount, suspendedOrgCount);
    }

    // SAFE FIELD-SLICED VIEWS!
    function getOrganizationMain(address addr)
        external
        view
        returns (
            address orgAddress,
            string memory name,
            OrganizationType orgType,
            OrganizationStatus status,
            string memory country,
            string memory state,
            string memory city
        )
    {
        Organization storage org = organizations[addr];
        orgAddress = org.orgAddress;
        name = org.name;
        orgType = org.orgType;
        status = org.status;
        country = org.country;
        state = org.state;
        city = org.city;
    }

    function getOrganizationContact(address addr)
        external
        view
        returns (
            string memory registrationNumber,
            string memory website,
            string memory email,
            string memory metadataUri
        )
    {
        Organization storage org = organizations[addr];
        registrationNumber = org.registrationNumber;
        website = org.website;
        email = org.email;
        metadataUri = org.metadataUri;
    }

    function getOrganizationStatus(address addr)
        external
        view
        returns (
            uint256 registeredAt,
            uint256 lastUpdated,
            bool canIssueCertificates,
            bytes32 kycHash,
            uint256 trustScore,
            uint256 certificatesIssued,
            uint256 certificatesRevoked
        )
    {
        Organization storage org = organizations[addr];
        registeredAt = org.registeredAt;
        lastUpdated = org.lastUpdated;
        canIssueCertificates = org.canIssueCertificates;
        kycHash = org.kycHash;
        trustScore = org.trustScore;
        certificatesIssued = org.certificatesIssued;
        certificatesRevoked = org.certificatesRevoked;
    }

    function getAccreditations(address addr) external view returns (AccreditationType[] memory) {
        Organization storage org = organizations[addr];
        return org.accreditations;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IVerificationLogger.sol";

contract ContractRegistry is AccessControl {
    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");

    struct ContractInfo {
        address contractAddress;
        string name;
        string version;
        uint256 deployedAt;
        bool isActive;
        bytes32 codeHash;
    }

    mapping(string => ContractInfo) public contracts;
    mapping(address => string) public addressToName;
    string[] public contractNames;

    IVerificationLogger public verificationLogger;

    event ContractRegistered(
        string indexed name,
        address indexed contractAddress,
        string version
    );
    event ContractUpdated(
        string indexed name,
        address indexed oldAddress,
        address indexed newAddress
    );
    event ContractDeactivated(
        string indexed name,
        address indexed contractAddress
    );

    constructor(address _verificationLogger) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
    }

    function registerContract(
        string memory name,
        address contractAddress,
        string memory version
    ) public onlyRole(REGISTRY_ADMIN_ROLE) {
        require(contractAddress != address(0), "Invalid contract address");
        require(contractAddress.code.length > 0, "Address is not a contract");
        require(
            bytes(name).length > 0 && bytes(name).length <= 50,
            "Invalid name length"
        );
        require(
            bytes(version).length > 0 && bytes(version).length <= 20,
            "Invalid version length"
        );

        bool isNewContract = contracts[name].contractAddress == address(0);

        if (isNewContract) {
            contractNames.push(name);
        } else {
            // Remove old address mapping only if it exists
            address oldAddress = contracts[name].contractAddress;
            if (oldAddress != address(0)) {
                delete addressToName[oldAddress];
            }
        }

        bytes32 codeHash = _getCodeHash(contractAddress);
        require(codeHash != bytes32(0), "Invalid contract code");

        contracts[name] = ContractInfo({
            contractAddress: contractAddress,
            name: name,
            version: version,
            deployedAt: block.timestamp,
            isActive: true,
            codeHash: codeHash
        });

        addressToName[contractAddress] = name;

        if (address(verificationLogger) != address(0)) {
            verificationLogger.logEvent(
                isNewContract ? "CONTRACT_REGISTERED" : "CONTRACT_UPDATED",
                msg.sender,
                keccak256(abi.encodePacked(name, contractAddress, version))
            );
        }

        if (isNewContract) {
            emit ContractRegistered(name, contractAddress, version);
        } else {
            emit ContractUpdated(name, address(0), contractAddress);
        }
    }

    function updateContract(
        string memory name,
        address newAddress,
        string memory newVersion
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(
            contracts[name].contractAddress != address(0),
            "Contract not found"
        );
        require(newAddress != address(0), "Invalid new address");
        require(contracts[name].contractAddress != newAddress, "Same address");

        address oldAddress = contracts[name].contractAddress;

        // Remove old address mapping
        delete addressToName[oldAddress];

        // Update contract info
        contracts[name].contractAddress = newAddress;
        contracts[name].version = newVersion;
        contracts[name].deployedAt = block.timestamp;
        contracts[name].codeHash = _getCodeHash(newAddress);

        addressToName[newAddress] = name;

        verificationLogger.logEvent(
            "CONTRACT_UPDATED",
            msg.sender,
            keccak256(abi.encodePacked(name, oldAddress, newAddress))
        );

        emit ContractUpdated(name, oldAddress, newAddress);
    }

    function deactivateContract(
        string memory name
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(
            contracts[name].contractAddress != address(0),
            "Contract not found"
        );
        require(contracts[name].isActive, "Contract already inactive");

        contracts[name].isActive = false;

        verificationLogger.logEvent(
            "CONTRACT_DEACTIVATED",
            msg.sender,
            keccak256(abi.encodePacked(name))
        );

        emit ContractDeactivated(name, contracts[name].contractAddress);
    }

    function reactivateContract(
        string memory name
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(
            contracts[name].contractAddress != address(0),
            "Contract not found"
        );
        require(!contracts[name].isActive, "Contract already active");

        contracts[name].isActive = true;

        verificationLogger.logEvent(
            "CONTRACT_REACTIVATED",
            msg.sender,
            keccak256(abi.encodePacked(name))
        );
    }

    function getContractAddress(
        string memory name
    ) external view returns (address) {
        require(contracts[name].isActive, "Contract inactive or not found");
        return contracts[name].contractAddress;
    }

    function getContractInfo(
        string memory name
    ) external view returns (ContractInfo memory) {
        return contracts[name];
    }

    function getContractName(
        address contractAddress
    ) external view returns (string memory) {
        return addressToName[contractAddress];
    }

    function getAllContracts() external view returns (string[] memory) {
        return contractNames;
    }

    function getActiveContracts() external view returns (string[] memory) {
        uint256 activeCount = 0;

        // Count active contracts
        for (uint256 i = 0; i < contractNames.length; i++) {
            if (contracts[contractNames[i]].isActive) {
                activeCount++;
            }
        }

        // Collect active contracts
        string[] memory activeContracts = new string[](activeCount);
        uint256 index = 0;

        for (uint256 i = 0; i < contractNames.length; i++) {
            if (contracts[contractNames[i]].isActive) {
                activeContracts[index] = contractNames[i];
                index++;
            }
        }

        return activeContracts;
    }

    function isContractRegistered(
        string memory name
    ) external view returns (bool) {
        return contracts[name].contractAddress != address(0);
    }

    function isContractActive(string memory name) external view returns (bool) {
        return
            contracts[name].contractAddress != address(0) &&
            contracts[name].isActive;
    }

    function verifyContract(
        string memory name,
        address expectedAddress
    ) external view returns (bool) {
        ContractInfo memory info = contracts[name];
        return info.contractAddress == expectedAddress && info.isActive;
    }

    function getContractCodeHash(
        string memory name
    ) external view returns (bytes32) {
        return contracts[name].codeHash;
    }

    function verifyCodeIntegrity(
        string memory name
    ) external view returns (bool) {
        ContractInfo memory info = contracts[name];
        if (info.contractAddress == address(0)) return false;

        bytes32 currentCodeHash = _getCodeHash(info.contractAddress);
        return currentCodeHash == info.codeHash;
    }

    function batchRegisterContracts(
        string[] memory names,
        address[] memory addresses,
        string[] memory versions
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        uint256 length = names.length;
        require(
            length == addresses.length && addresses.length == versions.length,
            "Array lengths must match"
        );
        require(length > 0 && length <= 20, "Invalid batch size"); // Limit batch size for gas efficiency

        unchecked {
            for (uint256 i = 0; i < length; ++i) {
                registerContract(names[i], addresses[i], versions[i]);
            }
        }
    }

    function getContractStats()
        external
        view
        returns (
            uint256 totalContracts,
            uint256 activeContracts,
            uint256 inactiveContracts
        )
    {
        totalContracts = contractNames.length;
        uint256 active = 0;

        for (uint256 i = 0; i < contractNames.length; i++) {
            if (contracts[contractNames[i]].isActive) {
                active++;
            }
        }

        activeContracts = active;
        inactiveContracts = totalContracts - active;
    }

    function _getCodeHash(
        address contractAddress
    ) private view returns (bytes32) {
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(contractAddress)
        }
        return codeHash;
    }
}
